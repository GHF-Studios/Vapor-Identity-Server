use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::profiles::current_profile_from_headers;
use crate::types::AppState;
use crate::util::{html_escape, public_origin, same_origin_browser_request, unix_now_i64};

const AUTHORIZATION_TTL_SECONDS: i64 = 10 * 60;
const REQUEST_CREDENTIAL_TTL_SECONDS: i64 = 3 * 60;
const POLL_INTERVAL_SECONDS: i64 = 3;
const MAX_ACTIVE_AUTHORIZATIONS: i64 = 1000;
const MAX_OPEN_AUTHORIZATIONS_PER_FINGERPRINT: i64 = 3;
const SSH_REQUEST_SCOPE: &str = "platform:ssh-access:request";
const ALLOWED_CAPABILITIES: &[&str] = &["vapor_deploy", "vapor_service_control", "host_admin"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartSshAuthorizationRequest {
    ssh_fingerprint: String,
    purpose: String,
    requested_capabilities: Vec<String>,
    requested_duration_seconds: i64,
}

#[derive(Serialize)]
struct StartSshAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in_seconds: i64,
    poll_interval_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PollSshAuthorizationRequest {
    device_code: String,
}

#[derive(Serialize)]
struct PollSshAuthorizationResponse {
    status: &'static str,
    credential_token: Option<String>,
    credential_expires_at_unix: Option<i64>,
    poll_interval_seconds: i64,
}

#[derive(Deserialize)]
pub(crate) struct SshAuthorizationQuery {
    user_code: String,
}

#[derive(Deserialize)]
pub(crate) struct ApproveSshAuthorizationForm {
    user_code: String,
    action: String,
}

pub(crate) async fn start_ssh_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StartSshAuthorizationRequest>,
) -> Response {
    if !valid_fingerprint(&request.ssh_fingerprint)
        || request.purpose.trim().is_empty()
        || request.purpose.len() > 500
        || request.purpose.chars().any(char::is_control)
        || !(3600..=8 * 60 * 60).contains(&request.requested_duration_seconds)
    {
        return (
            StatusCode::BAD_REQUEST,
            "invalid SSH authorization request\n",
        )
            .into_response();
    }
    let capabilities = match normalize_capabilities(&request.requested_capabilities) {
        Some(capabilities) => capabilities,
        None => return (StatusCode::BAD_REQUEST, "invalid SSH capabilities\n").into_response(),
    };

    let now = unix_now_i64();
    let _ = sqlx::query("DELETE FROM cli_ssh_authorizations WHERE expires_at_unix < ?")
        .bind(now - 24 * 60 * 60)
        .execute(&state.pool)
        .await;
    let active_count: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM cli_ssh_authorizations
         WHERE status IN ('pending', 'approved') AND expires_at_unix > ?",
    )
    .bind(now)
    .fetch_one(&state.pool)
    .await
    {
        Ok(count) => count,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if active_count >= MAX_ACTIVE_AUTHORIZATIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization service is busy; retry shortly\n",
        )
            .into_response();
    }
    let fingerprint_count: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM cli_ssh_authorizations
         WHERE ssh_fingerprint = ? AND status IN ('pending', 'approved') AND expires_at_unix > ?",
    )
    .bind(request.ssh_fingerprint.trim())
    .bind(now)
    .fetch_one(&state.pool)
    .await
    {
        Ok(count) => count,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if fingerprint_count >= MAX_OPEN_AUTHORIZATIONS_PER_FINGERPRINT {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many active authorizations for this SSH key\n",
        )
            .into_response();
    }
    let device_code = format!(
        "vap_cli_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let user_code = Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase();
    let id = Uuid::new_v4().to_string();
    let inserted = sqlx::query(
        "INSERT INTO cli_ssh_authorizations
         (id, device_code_hash, user_code_hash, ssh_fingerprint, purpose, capabilities,
          requested_duration_seconds, status, created_at_unix, expires_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
    )
    .bind(id)
    .bind(digest(&device_code))
    .bind(digest(&user_code))
    .bind(request.ssh_fingerprint.trim())
    .bind(request.purpose.trim())
    .bind(capabilities.join(" "))
    .bind(request.requested_duration_seconds)
    .bind(now)
    .bind(now + AUTHORIZATION_TTL_SECONDS)
    .execute(&state.pool)
    .await;
    if inserted.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let origin = public_origin(&state.config, &headers);
    let verification_uri = format!("{origin}/cli/ssh/authorize?user_code={user_code}");
    (
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(StartSshAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            expires_in_seconds: AUTHORIZATION_TTL_SECONDS,
            poll_interval_seconds: POLL_INTERVAL_SECONDS,
        }),
    )
        .into_response()
}

pub(crate) async fn ssh_authorization_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SshAuthorizationQuery>,
) -> Response {
    let Some(user_code) = normalize_user_code(&query.user_code) else {
        return (StatusCode::BAD_REQUEST, "invalid authorization code\n").into_response();
    };
    let Some(row) = active_authorization(&state, &user_code).await else {
        return (
            StatusCode::GONE,
            "this SSH authorization has expired or was already used\n",
        )
            .into_response();
    };
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let page = render_authorization_page(&user_code, &row, current.is_some());
    let mut response = Html(page).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response
}

pub(crate) async fn approve_ssh_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApproveSshAuthorizationForm>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                "sign in to Vapor Identity first\n",
            )
                .into_response()
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let Some(user_code) = normalize_user_code(&form.user_code) else {
        return (StatusCode::BAD_REQUEST, "invalid authorization code\n").into_response();
    };
    if !matches!(form.action.as_str(), "approve" | "deny") {
        return (StatusCode::BAD_REQUEST, "invalid action\n").into_response();
    }
    let status = if form.action == "approve" {
        "approved"
    } else {
        "denied"
    };
    let now = unix_now_i64();
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let fingerprint: String = match sqlx::query_scalar(
        "SELECT ssh_fingerprint FROM cli_ssh_authorizations
         WHERE user_code_hash = ? AND status = 'pending' AND expires_at_unix > ?",
    )
    .bind(digest(&user_code))
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(fingerprint)) => fingerprint,
        Ok(None) => {
            return (StatusCode::GONE, "authorization is no longer pending\n").into_response()
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let updated = sqlx::query(
        "UPDATE cli_ssh_authorizations
         SET status = ?, approved_by_profile_id = ?
         WHERE user_code_hash = ? AND status = 'pending' AND expires_at_unix > ?",
    )
    .bind(status)
    .bind(&current.profile_id)
    .bind(digest(&user_code))
    .bind(now)
    .execute(&mut *tx)
    .await;
    match updated {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return (StatusCode::GONE, "authorization is no longer pending\n").into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let event_type = if status == "approved" {
        "cli_ssh_authorization_approved"
    } else {
        "cli_ssh_authorization_denied"
    };
    if sqlx::query(
        "INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(event_type)
    .bind(&current.profile_id)
    .bind(&current.profile_id)
    .bind(now)
    .bind(format!("fingerprint={fingerprint}"))
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let message = if status == "approved" {
        "Vapor CLI may submit this one SSH access request. The Platform dashboard must still approve the actual grant."
    } else {
        "Vapor CLI SSH request authorization denied."
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>SSH request authorization · Vapor</title><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\"><main id=\"admin-content\"><p class=\"eyebrow\">Vapor Identity</p><h1>Authorization recorded</h1><p>{}</p><p>You can return to Vapor CLI.</p></main></html>",
        html_escape(message)
    );
    let mut response = Html(body).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(crate) async fn poll_ssh_authorization(
    State(state): State<AppState>,
    Json(request): Json<PollSshAuthorizationRequest>,
) -> Response {
    if request.device_code.len() != 8 + 64
        || !request.device_code.starts_with("vap_cli_")
        || !request.device_code[8..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return (StatusCode::BAD_REQUEST, "invalid device code\n").into_response();
    }
    let now = unix_now_i64();
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let row = match sqlx::query(
        "SELECT id, ssh_fingerprint, purpose, capabilities, requested_duration_seconds,
                status, expires_at_unix, last_poll_at_unix
         FROM cli_ssh_authorizations WHERE device_code_hash = ?",
    )
    .bind(digest(&request.device_code))
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "unknown device code\n").into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let id: String = row.get("id");
    let fingerprint: String = row.get("ssh_fingerprint");
    let purpose: String = row.get("purpose");
    let capabilities: String = row.get("capabilities");
    let requested_duration_seconds: i64 = row.get("requested_duration_seconds");
    let status: String = row.get("status");
    let expires_at: i64 = row.get("expires_at_unix");
    let last_poll: Option<i64> = row.get("last_poll_at_unix");
    if expires_at <= now || status == "consumed" {
        return (StatusCode::GONE, "authorization expired or consumed\n").into_response();
    }
    if last_poll.is_some_and(|last| now - last < POLL_INTERVAL_SECONDS) {
        return (StatusCode::TOO_MANY_REQUESTS, "poll interval not elapsed\n").into_response();
    }
    if sqlx::query("UPDATE cli_ssh_authorizations SET last_poll_at_unix = ? WHERE id = ?")
        .bind(now)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    match status.as_str() {
        "pending" => {
            if tx.commit().await.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            return (
                StatusCode::OK,
                Json(PollSshAuthorizationResponse {
                    status: "pending",
                    credential_token: None,
                    credential_expires_at_unix: None,
                    poll_interval_seconds: POLL_INTERVAL_SECONDS,
                }),
            )
                .into_response();
        }
        "denied" => {
            if tx.commit().await.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            return (
                StatusCode::OK,
                Json(PollSshAuthorizationResponse {
                    status: "denied",
                    credential_token: None,
                    credential_expires_at_unix: None,
                    poll_interval_seconds: POLL_INTERVAL_SECONDS,
                }),
            )
                .into_response();
        }
        "approved" => {}
        _ => return StatusCode::CONFLICT.into_response(),
    }

    let token = format!(
        "vap_req_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let credential_id = Uuid::new_v4().to_string();
    let credential_expires = now + REQUEST_CREDENTIAL_TTL_SECONDS;
    let label = format!("Vapor CLI one-request SSH ({fingerprint})");
    let request_hash = ssh_request_binding_hash(
        &fingerprint,
        &purpose,
        &capabilities,
        requested_duration_seconds,
    );
    if sqlx::query(
        "INSERT INTO automation_credentials
         (id, token_hash, label, scopes, created_by_profile_id, created_at_unix,
          expires_at_unix, single_use, use_count, bound_ssh_fingerprint, bound_ssh_request_hash)
         SELECT ?, ?, ?, ?, approved_by_profile_id, ?, ?, 1, 0, ssh_fingerprint, ?
         FROM cli_ssh_authorizations WHERE id = ? AND status = 'approved'",
    )
    .bind(&credential_id)
    .bind(credential_digest(&token))
    .bind(&label)
    .bind(SSH_REQUEST_SCOPE)
    .bind(now)
    .bind(credential_expires)
    .bind(&request_hash)
    .bind(&id)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if sqlx::query(
        "INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail)
         SELECT 'cli_ssh_request_authorized', approved_by_profile_id, approved_by_profile_id, ?, ?
         FROM cli_ssh_authorizations WHERE id = ?",
    )
    .bind(now)
    .bind(format!("fingerprint={fingerprint};authorization_id={id}"))
    .bind(&id)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let consumed = sqlx::query(
        "UPDATE cli_ssh_authorizations SET status = 'consumed', consumed_at_unix = ?
         WHERE id = ? AND status = 'approved' AND expires_at_unix > ?",
    )
    .bind(now)
    .bind(&id)
    .bind(now)
    .execute(&mut *tx)
    .await;
    if !matches!(consumed, Ok(result) if result.rows_affected() == 1) || tx.commit().await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        StatusCode::OK,
        Json(PollSshAuthorizationResponse {
            status: "approved",
            credential_token: Some(token),
            credential_expires_at_unix: Some(credential_expires),
            poll_interval_seconds: POLL_INTERVAL_SECONDS,
        }),
    )
        .into_response()
}

struct AuthorizationView {
    fingerprint: String,
    purpose: String,
    capabilities: String,
    duration: i64,
}

async fn active_authorization(state: &AppState, user_code: &str) -> Option<AuthorizationView> {
    let row = sqlx::query(
        "SELECT ssh_fingerprint, purpose, capabilities, requested_duration_seconds
         FROM cli_ssh_authorizations WHERE user_code_hash = ? AND status = 'pending' AND expires_at_unix > ?",
    )
    .bind(digest(user_code))
    .bind(unix_now_i64())
    .fetch_optional(&state.pool)
    .await
    .ok()??;
    Some(AuthorizationView {
        fingerprint: row.get("ssh_fingerprint"),
        purpose: row.get("purpose"),
        capabilities: row.get("capabilities"),
        duration: row.get("requested_duration_seconds"),
    })
}

fn render_authorization_page(user_code: &str, view: &AuthorizationView, signed_in: bool) -> String {
    let purpose = html_escape(&view.purpose);
    let fingerprint = html_escape(&view.fingerprint);
    let capabilities = html_escape(&view.capabilities.replace(' ', ", "));
    let duration_hours = view.duration / 3600;
    let controls = if signed_in {
        format!(
            "<form method=\"post\" action=\"/cli/ssh/authorize\"><input type=\"hidden\" name=\"user_code\" value=\"{}\"><button name=\"action\" value=\"approve\">Authorize this request</button> <button name=\"action\" value=\"deny\">Deny</button></form>",
            html_escape(user_code)
        )
    } else {
        "<p><a href=\"/login\" target=\"_blank\" rel=\"noopener\">Sign in to Vapor Identity</a> in a new tab, then return here and reload this page.</p>".to_string()
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Authorize SSH request · Vapor</title><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\"></head><body><main id=\"admin-content\"><p class=\"eyebrow\">Vapor Identity · one-time authorization</p><h1>Vapor CLI requests permission to submit SSH access request</h1><dl><dt>SSH key fingerprint</dt><dd><code>{fingerprint}</code></dd><dt>Purpose</dt><dd>{purpose}</dd><dt>Requested capabilities</dt><dd>{capabilities}</dd><dt>Requested duration</dt><dd>{duration_hours} hour(s)</dd></dl><p>This authorizes submission of this request only. It does not grant SSH access. A Platform operator must still review and approve the actual access grant.</p>{controls}</main></body></html>"
    )
}

fn normalize_capabilities(values: &[String]) -> Option<Vec<String>> {
    if values.is_empty() || values.len() > ALLOWED_CAPABILITIES.len() {
        return None;
    }
    let mut result = BTreeSet::new();
    for value in values {
        if !ALLOWED_CAPABILITIES.contains(&value.as_str()) || !result.insert(value.as_str()) {
            return None;
        }
    }
    if result.contains("host_admin") && result.len() != 1 {
        return None;
    }
    Some(result.into_iter().map(str::to_owned).collect())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 50
        && value.starts_with("SHA256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn normalize_user_code(value: &str) -> Option<String> {
    let normalized = value.trim().replace('-', "").to_ascii_uppercase();
    (normalized.len() == 12 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn digest(value: &str) -> String {
    let hash = Sha256::digest(value.as_bytes());
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ssh_request_binding_hash(
    fingerprint: &str,
    purpose: &str,
    capabilities: &str,
    duration_seconds: i64,
) -> String {
    let canonical = format!("{fingerprint}\n{purpose}\n{capabilities}\n{duration_seconds}");
    digest(&canonical)
}

fn credential_digest(token: &str) -> String {
    use crate::automation_credentials::credential_digest;
    credential_digest(token)
}
