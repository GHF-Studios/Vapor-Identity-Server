use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::automation_credentials::{
    request_credential_principal, CredentialScope, RequestCredentialPrincipal,
};
use crate::profiles::{
    current_profile_from_headers, profile_has_dual_identity, profile_id_by_linked_identities,
};
use crate::types::AppState;
use crate::util::{
    same_origin_browser_request, unix_now_i64, valid_github_login, valid_steam_id64,
};

const REQUEST_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const EXPIRY_SWEEP_BATCH_SIZE: i64 = 100;
const EXPIRY_SWEEP_MAX_BATCHES: usize = 10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatePermissionRequest {
    pub(crate) action: String,
    pub(crate) role: String,
    pub(crate) steam_id64: String,
    pub(crate) github_login: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovePermissionRequest {
    expected_version: i64,
    confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RejectPermissionRequest {
    expected_version: i64,
    reason: String,
    confirmed: bool,
}

#[derive(Serialize)]
struct PermissionRequestCreated {
    id: String,
    status: &'static str,
    version: i64,
    expires_at_unix: i64,
}

#[derive(Serialize)]
struct PermissionRequestSummary {
    id: String,
    requester_profile_id: String,
    requester_kind: String,
    action: String,
    role: String,
    steam_id64: String,
    github_login: String,
    status: String,
    version: i64,
    created_at_unix: i64,
    expires_at_unix: i64,
    decided_at_unix: Option<i64>,
    decision_reason: Option<String>,
}

struct RequestActor {
    profile_id: String,
    credential: Option<RequestCredentialPrincipal>,
}

pub(crate) async fn expire_pending_permission_requests(
    pool: &SqlitePool,
    now: i64,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    serialize_permission_mutation(&mut tx).await?;
    let rows = sqlx::query(
        "SELECT id, resolved_profile_id, version
         FROM permission_requests
         WHERE status = 'pending' AND expires_at_unix <= ?
         ORDER BY expires_at_unix, created_at_unix, id
         LIMIT ?",
    )
    .bind(now)
    .bind(EXPIRY_SWEEP_BATCH_SIZE)
    .fetch_all(&mut *tx)
    .await?;

    let mut expired_count = 0;
    for row in rows {
        let id: String = row.get("id");
        let subject_profile_id: String = row.get("resolved_profile_id");
        let version: i64 = row.get("version");
        let updated = sqlx::query(
            "UPDATE permission_requests
             SET status = 'expired', version = version + 1, decided_at_unix = ?
             WHERE id = ? AND status = 'pending' AND version = ? AND expires_at_unix <= ?",
        )
        .bind(now)
        .bind(&id)
        .bind(version)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 1 {
            audit_event_in_tx(
                &mut tx,
                "permission_request_expired",
                None,
                Some(&subject_profile_id),
                &format!("request_id={id}"),
            )
            .await?;
            expired_count += 1;
        }
    }
    tx.commit().await?;
    Ok(expired_count)
}

pub(crate) async fn sweep_expired_permission_requests(
    pool: &SqlitePool,
) -> Result<u64, sqlx::Error> {
    let mut total = 0;
    for _ in 0..EXPIRY_SWEEP_MAX_BATCHES {
        let expired = expire_pending_permission_requests(pool, unix_now_i64()).await?;
        total += expired;
        if expired < EXPIRY_SWEEP_BATCH_SIZE as u64 {
            return Ok(total);
        }
    }
    Ok(total)
}

pub(crate) async fn create_permission_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePermissionRequest>,
) -> Response {
    let actor = match request_actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if actor.credential.is_none() && !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }

    let action = request.action.trim();
    let role = request.role.trim();
    let steam_id64 = request.steam_id64.trim();
    let github_login = request.github_login.trim();
    if !matches!(action, "grant" | "revoke") {
        return (StatusCode::BAD_REQUEST, "action must be grant or revoke\n").into_response();
    }
    if !matches!(role, "root" | "content-developer") {
        return (
            StatusCode::BAD_REQUEST,
            "role must be root or content-developer\n",
        )
            .into_response();
    }
    if !valid_steam_id64(steam_id64) || !valid_github_login(github_login) {
        return (
            StatusCode::BAD_REQUEST,
            "valid linked SteamID64 and GitHub login required\n",
        )
            .into_response();
    }
    let subject_id =
        match profile_id_by_linked_identities(&state.pool, steam_id64, github_login).await {
            Ok(Some(profile_id)) => profile_id,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    "linked Steam/GitHub profile not found\n",
                )
                    .into_response()
            }
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
    match profile_has_dual_identity(&state.pool, &subject_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                "elevated roles require linked Steam and GitHub identities\n",
            )
                .into_response()
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let role_active_at_request =
        match crate::profiles::profile_has_role(&state.pool, &subject_id, role).await {
            Ok(active) => active,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };

    let now = unix_now_i64();
    let expires_at = now + REQUEST_TTL_SECONDS;
    let id = Uuid::new_v4().to_string();
    let body_hash = crate::automation_credentials::credential_digest(&format!(
        "{action}\n{role}\n{steam_id64}\n{github_login}"
    ));
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let result = sqlx::query(
        "INSERT INTO permission_requests
         (id, body_hash, action, role, steam_id64, github_login, resolved_profile_id,
          requester_profile_id, requester_credential_id, role_active_at_request, status, version, created_at_unix, expires_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?)",
    )
    .bind(&id)
    .bind(body_hash)
    .bind(action)
    .bind(role)
    .bind(steam_id64)
    .bind(github_login)
    .bind(&subject_id)
    .bind(&actor.profile_id)
    .bind(actor.credential.as_ref().map(|credential| credential.credential_id.as_str()))
    .bind(i64::from(role_active_at_request))
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await;
    if result.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if audit_event_in_tx(
        &mut tx,
        "permission_request_created",
        Some(&actor.profile_id),
        Some(&subject_id),
        &format!("request_id={id};action={action};role={role}"),
    )
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        StatusCode::ACCEPTED,
        Json(PermissionRequestCreated {
            id,
            status: "pending",
            version: 1,
            expires_at_unix: expires_at,
        }),
    )
        .into_response()
}

pub(crate) async fn list_permission_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let actor = match request_actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if actor.credential.is_none() && !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }
    let query = if let Some(credential) = &actor.credential {
        sqlx::query(
            "SELECT id, requester_profile_id, requester_credential_id, action, role, steam_id64, github_login, status, version,
                    created_at_unix, expires_at_unix, decided_at_unix, decision_reason
             FROM permission_requests WHERE requester_credential_id = ?
             ORDER BY created_at_unix DESC LIMIT 200",
        )
        .bind(&credential.credential_id)
    } else {
        match root_authorized(&state, &headers).await {
            Ok(true) => {}
            Ok(false) => return (StatusCode::FORBIDDEN, "root role required\n").into_response(),
            Err(response) => return response,
        }
        sqlx::query(
            "SELECT id, requester_profile_id, requester_credential_id, action, role, steam_id64, github_login, status, version,
                    created_at_unix, expires_at_unix, decided_at_unix, decision_reason
             FROM permission_requests ORDER BY created_at_unix DESC LIMIT 200",
        )
    };
    match query.fetch_all(&state.pool).await {
        Ok(rows) => {
            let requests = rows
                .into_iter()
                .map(|row| PermissionRequestSummary {
                    id: row.get("id"),
                    requester_profile_id: row.get("requester_profile_id"),
                    requester_kind: if row
                        .get::<Option<String>, _>("requester_credential_id")
                        .is_some()
                    {
                        "request credential".to_owned()
                    } else {
                        "interactive session".to_owned()
                    },
                    action: row.get("action"),
                    role: row.get("role"),
                    steam_id64: row.get("steam_id64"),
                    github_login: row.get("github_login"),
                    status: row.get("status"),
                    version: row.get("version"),
                    created_at_unix: row.get("created_at_unix"),
                    expires_at_unix: row.get("expires_at_unix"),
                    decided_at_unix: row.get("decided_at_unix"),
                    decision_reason: row.get("decision_reason"),
                })
                .collect::<Vec<_>>();
            Json(requests).into_response()
        }
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

pub(crate) async fn approve_permission_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ApprovePermissionRequest>,
) -> Response {
    if request.expected_version < 1 || !request.confirmed {
        return (
            StatusCode::BAD_REQUEST,
            "positive expected_version and explicit confirmation required\n",
        )
            .into_response();
    }
    if !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }
    let actor = match root_session_actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if serialize_permission_mutation(&mut tx).await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let row = match sqlx::query(
        "SELECT action, role, steam_id64, github_login, resolved_profile_id, body_hash,
                status, version, expires_at_unix, role_active_at_request, requester_profile_id
         FROM permission_requests WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let status: String = row.get("status");
    let version: i64 = row.get("version");
    let expires_at: i64 = row.get("expires_at_unix");
    let subject_profile_id: String = row.get("resolved_profile_id");
    if status != "pending" || version != request.expected_version {
        return (
            StatusCode::CONFLICT,
            "request is no longer pending at that version\n",
        )
            .into_response();
    }
    if expires_at <= unix_now_i64() {
        let now = unix_now_i64();
        let changed = sqlx::query(
            "UPDATE permission_requests
             SET status = 'expired', version = version + 1, decided_at_unix = ?
             WHERE id = ? AND status = 'pending' AND version = ? AND expires_at_unix <= ?",
        )
        .bind(now)
        .bind(&id)
        .bind(request.expected_version)
        .bind(now)
        .execute(&mut *tx)
        .await;
        if !matches!(changed, Ok(result) if result.rows_affected() == 1)
            || audit_event_in_tx(
                &mut tx,
                "permission_request_expired",
                None,
                Some(&subject_profile_id),
                &format!("request_id={id}"),
            )
            .await
            .is_err()
            || tx.commit().await.is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        return (StatusCode::GONE, "permission request expired\n").into_response();
    }
    let action: String = row.get("action");
    let role: String = row.get("role");
    let steam_id64: String = row.get("steam_id64");
    let github_login: String = row.get("github_login");
    let resolved_profile_id: String = row.get("resolved_profile_id");
    let body_hash: String = row.get("body_hash");
    let role_active_at_request: i64 = row.get("role_active_at_request");
    let requester_profile_id: String = row.get("requester_profile_id");
    let expected_hash = crate::automation_credentials::credential_digest(&format!(
        "{action}\n{role}\n{steam_id64}\n{github_login}"
    ));
    if body_hash != expected_hash {
        return (
            StatusCode::CONFLICT,
            "permission request integrity check failed\n",
        )
            .into_response();
    }
    let identity_is_still_linked: i64 = match sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM profiles p
            JOIN steam_accounts s ON s.profile_id = p.id
            JOIN github_accounts g ON g.profile_id = p.id
            WHERE p.id = ? AND p.disabled_at_unix IS NULL
              AND s.steam_id64 = ? AND g.github_login = ?
        )",
    )
    .bind(&resolved_profile_id)
    .bind(&steam_id64)
    .bind(&github_login)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if identity_is_still_linked != 1 {
        if mark_stale(
            &mut tx,
            &id,
            request.expected_version,
            &actor,
            "linked identity changed",
        )
        .await
        .is_err()
            || tx.commit().await.is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        return (
            StatusCode::CONFLICT,
            "permission request became stale; create a new request\n",
        )
            .into_response();
    }
    let current_role_active: i64 = match sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM profile_roles WHERE profile_id = ? AND role = ? AND revoked_at_unix IS NULL)",
    )
    .bind(&resolved_profile_id)
    .bind(&role)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if current_role_active != role_active_at_request {
        if mark_stale(
            &mut tx,
            &id,
            request.expected_version,
            &actor,
            "subject role state changed",
        )
        .await
        .is_err()
            || tx.commit().await.is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        return (
            StatusCode::CONFLICT,
            "permission request became stale; create a new request\n",
        )
            .into_response();
    }
    let subject_is_root: i64 = if action == "revoke" && role == "content-developer" {
        match sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM profile_roles WHERE profile_id = ? AND role = 'root' AND revoked_at_unix IS NULL)")
            .bind(&resolved_profile_id).fetch_one(&mut *tx).await {
                Ok(value) => value,
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
    } else {
        0
    };
    if subject_is_root == 1 {
        return (
            StatusCode::CONFLICT,
            "root role implies content-developer; revoke root first\n",
        )
            .into_response();
    }
    let role_result = match action.as_str() {
        "grant" => grant_role_in_tx(&mut tx, &resolved_profile_id, &role, &actor).await,
        "revoke" => revoke_role_in_tx(&mut tx, &resolved_profile_id, &role, &actor).await,
        _ => Err(StatusCode::CONFLICT),
    };
    if let Err(status) = role_result {
        return (
            status,
            if status == StatusCode::CONFLICT {
                "role constraint prevents this change\n"
            } else {
                "failed to apply permission change\n"
            },
        )
            .into_response();
    }
    let now = unix_now_i64();
    let updated = sqlx::query(
        "UPDATE permission_requests
         SET status = 'succeeded', version = version + 1, decided_by_profile_id = ?, decided_at_unix = ?
         WHERE id = ? AND status = 'pending' AND version = ?",
    )
    .bind(&actor)
    .bind(now)
    .bind(&id)
    .bind(request.expected_version)
    .execute(&mut *tx)
    .await;
    if !matches!(updated, Ok(ref result) if result.rows_affected() == 1)
        || audit_event_in_tx(
            &mut tx,
            "permission_request_approved",
            Some(&actor),
            Some(&resolved_profile_id),
            &format!(
                "request_id={id};requester={requester_profile_id};action={action};role={role}"
            ),
        )
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({"id": id, "status": "succeeded", "version": request.expected_version + 1}))).into_response()
}

pub(crate) async fn reject_permission_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<RejectPermissionRequest>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }
    let actor = match root_session_actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let reason = request.reason.trim();
    if request.expected_version < 1
        || !request.confirmed
        || reason.is_empty()
        || reason.len() > 500
        || reason.chars().any(char::is_control)
    {
        return (
            StatusCode::BAD_REQUEST,
            "invalid request version or rejection reason\n",
        )
            .into_response();
    }
    let now = unix_now_i64();
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let result = sqlx::query(
        "UPDATE permission_requests
         SET status = 'rejected', version = version + 1, decided_by_profile_id = ?, decided_at_unix = ?, decision_reason = ?
         WHERE id = ? AND status = 'pending' AND version = ? AND expires_at_unix > ?",
    )
    .bind(&actor).bind(now).bind(reason).bind(&id).bind(request.expected_version).bind(now)
    .execute(&mut *tx).await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {
            if audit_event_in_tx(
                &mut tx,
                "permission_request_rejected",
                Some(&actor),
                None,
                &format!("request_id={id};reason={reason}"),
            )
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            (StatusCode::OK, Json(serde_json::json!({"id": id, "status": "rejected", "version": request.expected_version + 1}))).into_response()
        }
        Ok(_) => (
            StatusCode::CONFLICT,
            "request is expired or no longer pending at that version\n",
        )
            .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn request_actor(state: &AppState, headers: &HeaderMap) -> Result<RequestActor, Response> {
    if let Some(token) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        if let Some(credential) = request_credential_principal(
            &state.pool,
            token,
            CredentialScope::IdentityRoleRequestCreate,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?
        {
            return Ok(RequestActor {
                profile_id: credential.actor_profile_id.clone(),
                credential: Some(credential),
            });
        }
        return Err((
            StatusCode::UNAUTHORIZED,
            "valid identity request credential required\n",
        )
            .into_response());
    }
    let current = current_profile_from_headers(&state.pool, headers)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "root session or request credential required\n",
            )
                .into_response()
        })?;
    if !current.root_authorized {
        return Err((StatusCode::FORBIDDEN, "root role required\n").into_response());
    }
    Ok(RequestActor {
        profile_id: current.profile_id,
        credential: None,
    })
}

async fn root_authorized(state: &AppState, headers: &HeaderMap) -> Result<bool, Response> {
    Ok(current_profile_from_headers(&state.pool, headers)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?
        .is_some_and(|profile| profile.root_authorized))
}

async fn root_session_actor(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let current = current_profile_from_headers(&state.pool, headers)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "root session required\n").into_response())?;
    if !current.root_authorized {
        return Err((StatusCode::FORBIDDEN, "root role required\n").into_response());
    }
    Ok(current.profile_id)
}

async fn serialize_permission_mutation(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE service_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT), updated_at_unix = ? WHERE key = 'permission_mutation_lock'")
        .bind(unix_now_i64()).execute(&mut **tx).await?;
    Ok(())
}

async fn mark_stale(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    expected_version: i64,
    actor: &str,
    reason: &str,
) -> Result<(), sqlx::Error> {
    let now = unix_now_i64();
    let changed = sqlx::query(
        "UPDATE permission_requests
         SET status = 'stale', version = version + 1, decided_by_profile_id = ?, decided_at_unix = ?, decision_reason = ?
         WHERE id = ? AND status = 'pending' AND version = ?",
    )
    .bind(actor)
    .bind(now)
    .bind(reason)
    .bind(id)
    .bind(expected_version)
    .execute(&mut **tx)
    .await;
    match changed {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return Err(sqlx::Error::Protocol(
                "permission request changed concurrently".to_string(),
            ))
        }
        Err(error) => return Err(error),
    }
    audit_event_in_tx(
        tx,
        "permission_request_stale",
        Some(actor),
        None,
        &format!("request_id={id};reason={reason}"),
    )
    .await?;
    Ok(())
}

async fn grant_role_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    profile_id: &str,
    role: &str,
    actor: &str,
) -> Result<(), StatusCode> {
    let now = unix_now_i64();
    sqlx::query("INSERT INTO profile_roles (profile_id, role, granted_at_unix, revoked_at_unix) VALUES (?, ?, ?, NULL) ON CONFLICT(profile_id, role) DO UPDATE SET granted_at_unix = excluded.granted_at_unix, revoked_at_unix = NULL")
        .bind(profile_id).bind(role).bind(now).execute(&mut **tx).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let event = if role == "root" {
        "root_role_granted"
    } else {
        "profile_role_granted"
    };
    let detail = if role == "root" {
        String::new()
    } else {
        format!("role={role}")
    };
    audit_event_in_tx(tx, event, Some(actor), Some(profile_id), &detail)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn revoke_role_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    profile_id: &str,
    role: &str,
    actor: &str,
) -> Result<(), StatusCode> {
    let active: i64 = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM profile_roles WHERE profile_id = ? AND role = ? AND revoked_at_unix IS NULL)")
        .bind(profile_id).bind(role).fetch_one(&mut **tx).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if active == 0 {
        return Ok(());
    }
    if role == "root" {
        let roots: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT profile_id) FROM profile_roles WHERE role = 'root' AND revoked_at_unix IS NULL")
            .fetch_one(&mut **tx).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if roots <= 1 {
            return Err(StatusCode::CONFLICT);
        }
    }
    let now = unix_now_i64();
    sqlx::query("UPDATE profile_roles SET revoked_at_unix = ? WHERE profile_id = ? AND role = ? AND revoked_at_unix IS NULL")
        .bind(now).bind(profile_id).bind(role).execute(&mut **tx).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let event = if role == "root" {
        "root_role_revoked"
    } else {
        "profile_role_revoked"
    };
    let detail = if role == "root" {
        String::new()
    } else {
        format!("role={role}")
    };
    audit_event_in_tx(tx, event, Some(actor), Some(profile_id), &detail)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn audit_event_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    event_type: &str,
    actor: Option<&str>,
    subject: Option<&str>,
    detail: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail) VALUES (?, ?, ?, ?, ?)")
        .bind(event_type).bind(actor).bind(subject).bind(unix_now_i64()).bind(detail).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        approve_permission_request, create_permission_request, expire_pending_permission_requests,
        ApprovePermissionRequest, CreatePermissionRequest,
    };
    use crate::automation_credentials::credential_digest;
    use crate::config::AuthConfig;
    use crate::db::run_migrations;
    use crate::profiles::{create_identity_session, profile_has_role};
    use crate::types::AppState;
    use axum::body::to_bytes;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::Json;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::Arc;

    const API_TOKEN: &str =
        "vap_req_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    async fn state() -> AppState {
        let options = SqliteConnectOptions::new()
            .filename(":memory:")
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        AppState {
            pool,
            db_path: Arc::new("identity.sqlite3".into()),
            admin_token: Some("local-admin-token".to_string()),
            platform_request_authz_token: Some("0123456789abcdef".repeat(4)),
            config: Arc::new(AuthConfig {
                steam_app_id: 1,
                steam_auth_identity: "test".to_string(),
                steam_web_api_key: None,
                loocast_app_id: 1,
                authorization_service_token: None,
                platform_admin_authorization_service_token: None,
                artifact_admin_authorization_service_token: None,
                build_cache_admin_authorization_service_token: None,
                github_client_id: None,
                github_client_secret: None,
                dashboard_password: None,
                cookie_secure: true,
                cookie_path: "/".to_string(),
                public_origin: Some("https://vapor.example".to_string()),
            }),
            http: reqwest::Client::new(),
        }
    }

    async fn linked_profile(state: &AppState, id: &str, steam: &str, github: &str, root: bool) {
        let now = crate::util::unix_now_i64();
        sqlx::query("INSERT INTO profiles (id, created_at_unix) VALUES (?, ?)")
            .bind(id)
            .bind(now)
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO steam_accounts (steam_id64, profile_id, linked_at_unix, verified_at_unix) VALUES (?, ?, ?, ?)")
            .bind(steam).bind(id).bind(now).bind(now).execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO github_accounts (github_user_id, github_login, profile_id, linked_at_unix, verified_at_unix) VALUES (?, ?, ?, ?, ?)")
            .bind(id.bytes().next().unwrap_or(1) as i64).bind(github).bind(id).bind(now).bind(now).execute(&state.pool).await.unwrap();
        if root {
            sqlx::query("INSERT INTO profile_roles (profile_id, role, granted_at_unix) VALUES (?, 'root', ?)")
                .bind(id).bind(now).execute(&state.pool).await.unwrap();
        }
    }

    async fn root_headers(state: &AppState, root_id: &str) -> HeaderMap {
        let (_, token, _) = create_identity_session(&state.pool, root_id).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("vapor_identity_session={token}")).unwrap(),
        );
        headers.insert("origin", HeaderValue::from_static("https://vapor.example"));
        headers
    }

    fn request(
        action: &str,
        role: &str,
        steam: &str,
        github: &str,
    ) -> Json<CreatePermissionRequest> {
        Json(CreatePermissionRequest {
            action: action.to_string(),
            role: role.to_string(),
            steam_id64: steam.to_string(),
            github_login: github.to_string(),
        })
    }

    async fn request_id(response: axum::response::Response) -> String {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn request_is_pending_until_root_approves_and_applies_atomically() {
        let state = state().await;
        linked_profile(&state, "root-actor", "76561198111111111", "rootactor", true).await;
        linked_profile(
            &state,
            "developer-subject",
            "76561198111111112",
            "developer",
            false,
        )
        .await;
        let headers = root_headers(&state, "root-actor").await;
        let id = request_id(
            create_permission_request(
                State(state.clone()),
                headers.clone(),
                request(
                    "grant",
                    "content-developer",
                    "76561198111111112",
                    "developer",
                ),
            )
            .await,
        )
        .await;
        assert!(
            !profile_has_role(&state.pool, "developer-subject", "content-developer")
                .await
                .unwrap()
        );
        let response = approve_permission_request(
            State(state.clone()),
            headers,
            Path(id),
            Json(ApprovePermissionRequest {
                expected_version: 1,
                confirmed: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            profile_has_role(&state.pool, "developer-subject", "content-developer")
                .await
                .unwrap()
        );
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events WHERE event_type = 'permission_request_approved'").fetch_one(&state.pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn request_credential_can_submit_but_cannot_approve() {
        let state = state().await;
        linked_profile(&state, "root-actor", "76561198122222221", "rootactor", true).await;
        linked_profile(
            &state,
            "developer-subject",
            "76561198122222222",
            "developer",
            false,
        )
        .await;
        sqlx::query("INSERT INTO automation_credentials (id, token_hash, label, scopes, created_by_profile_id, created_at_unix, expires_at_unix) VALUES ('request-credential', ?, 'test', 'identity:role-request:create', 'root-actor', ?, ?)")
            .bind(credential_digest(API_TOKEN)).bind(crate::util::unix_now_i64()).bind(crate::util::unix_now_i64() + 3600).execute(&state.pool).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {API_TOKEN}")).unwrap(),
        );
        let id = request_id(
            create_permission_request(
                State(state.clone()),
                headers.clone(),
                request(
                    "grant",
                    "content-developer",
                    "76561198122222222",
                    "developer",
                ),
            )
            .await,
        )
        .await;
        let response = approve_permission_request(
            State(state),
            headers,
            Path(id),
            Json(ApprovePermissionRequest {
                expected_version: 1,
                confirmed: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn last_root_revoke_remains_pending_and_does_not_remove_access() {
        let state = state().await;
        linked_profile(&state, "only-root", "76561198133333331", "onlyroot", true).await;
        let headers = root_headers(&state, "only-root").await;
        let id = request_id(
            create_permission_request(
                State(state.clone()),
                headers.clone(),
                request("revoke", "root", "76561198133333331", "onlyroot"),
            )
            .await,
        )
        .await;
        let response = approve_permission_request(
            State(state.clone()),
            headers,
            Path(id.clone()),
            Json(ApprovePermissionRequest {
                expected_version: 1,
                confirmed: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(profile_has_role(&state.pool, "only-root", "root")
            .await
            .unwrap());
        let status: String =
            sqlx::query_scalar("SELECT status FROM permission_requests WHERE id = ?")
                .bind(id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(status, "pending");
    }

    #[tokio::test]
    async fn subject_role_change_marks_request_stale_instead_of_applying_it() {
        let state = state().await;
        linked_profile(&state, "root-actor", "76561198144444441", "rootactor", true).await;
        linked_profile(
            &state,
            "developer-subject",
            "76561198144444442",
            "developer",
            false,
        )
        .await;
        let headers = root_headers(&state, "root-actor").await;
        let id = request_id(
            create_permission_request(
                State(state.clone()),
                headers.clone(),
                request(
                    "grant",
                    "content-developer",
                    "76561198144444442",
                    "developer",
                ),
            )
            .await,
        )
        .await;
        sqlx::query("INSERT INTO profile_roles (profile_id, role, granted_at_unix) VALUES ('developer-subject', 'content-developer', ?)")
            .bind(crate::util::unix_now_i64()).execute(&state.pool).await.unwrap();
        let response = approve_permission_request(
            State(state.clone()),
            headers,
            Path(id.clone()),
            Json(ApprovePermissionRequest {
                expected_version: 1,
                confirmed: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let status: String =
            sqlx::query_scalar("SELECT status FROM permission_requests WHERE id = ?")
                .bind(id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(status, "stale");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'permission_request_stale'"
            )
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn expiry_sweep_persists_status_and_audit_once() {
        let state = state().await;
        linked_profile(&state, "requester", "76561198155555551", "requester", true).await;
        linked_profile(
            &state,
            "expired-subject",
            "76561198155555552",
            "expiredsubject",
            false,
        )
        .await;
        linked_profile(
            &state,
            "current-subject",
            "76561198155555553",
            "currentsubject",
            false,
        )
        .await;
        let headers = root_headers(&state, "requester").await;
        let expired_id = request_id(
            create_permission_request(
                State(state.clone()),
                headers.clone(),
                request(
                    "grant",
                    "content-developer",
                    "76561198155555552",
                    "expiredsubject",
                ),
            )
            .await,
        )
        .await;
        let current_id = request_id(
            create_permission_request(
                State(state.clone()),
                headers,
                request(
                    "grant",
                    "content-developer",
                    "76561198155555553",
                    "currentsubject",
                ),
            )
            .await,
        )
        .await;
        let now = crate::util::unix_now_i64();
        sqlx::query("UPDATE permission_requests SET expires_at_unix = ? WHERE id = ?")
            .bind(now - 1)
            .bind(&expired_id)
            .execute(&state.pool)
            .await
            .unwrap();

        let count = expire_pending_permission_requests(&state.pool, now)
            .await
            .unwrap();

        assert_eq!(count, 1);
        let expired: (String, i64, Option<i64>) = sqlx::query_as(
            "SELECT status, version, decided_at_unix FROM permission_requests WHERE id = ?",
        )
        .bind(&expired_id)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(expired.0, "expired");
        assert_eq!(expired.1, 2);
        assert_eq!(expired.2, Some(now));
        let current: (String, i64) =
            sqlx::query_as("SELECT status, version FROM permission_requests WHERE id = ?")
                .bind(&current_id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(current, ("pending".to_string(), 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'permission_request_expired' AND subject_profile_id = 'expired-subject' AND detail = ?",
            )
            .bind(format!("request_id={expired_id}"))
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            expire_pending_permission_requests(&state.pool, now)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'permission_request_expired' AND detail = ?",
            )
            .bind(format!("request_id={expired_id}"))
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            1
        );
    }
}
