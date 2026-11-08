#[cfg(test)]
mod tests {
    use super::{
        credential_digest, normalize_scopes, verify_automation_credential, CredentialScope,
        VerifyAutomationCredentialRequest,
    };
    use crate::config::AuthConfig;
    use crate::db::run_migrations;
    use crate::types::AppState;
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::Json;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::Arc;

    const SERVICE_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const REQUEST_TOKEN: &str =
        "vap_req_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn test_state() -> AppState {
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
            admin_token: None,
            platform_request_authz_token: Some(SERVICE_TOKEN.to_string()),
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
                operator_origin: None,
            }),
            http: reqwest::Client::new(),
        }
    }

    async fn insert_credential(state: &AppState, expires_at: i64, revoked_at: Option<i64>) {
        sqlx::query("INSERT INTO profiles (id, created_at_unix) VALUES ('actor-profile', 1)")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO automation_credentials
             (id, token_hash, label, scopes, created_by_profile_id, created_at_unix, expires_at_unix, revoked_at_unix)
             VALUES ('credential-id', ?, 'test', 'platform:deploy-request:create', 'actor-profile', 1, ?, ?)",
        )
        .bind(credential_digest(REQUEST_TOKEN))
        .bind(expires_at)
        .bind(revoked_at)
        .execute(&state.pool)
        .await
        .unwrap();
    }

    async fn root_headers(state: &AppState) -> HeaderMap {
        let now = crate::util::unix_now_i64();
        sqlx::query("INSERT INTO profiles (id, created_at_unix) VALUES ('root-profile', ?)")
            .bind(now)
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO steam_accounts (steam_id64, profile_id, linked_at_unix, verified_at_unix)
             VALUES ('76561198123456789', 'root-profile', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO github_accounts (github_user_id, github_login, profile_id, linked_at_unix, verified_at_unix)
             VALUES (12345, 'rootdev', 'root-profile', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO profile_roles (profile_id, role, granted_at_unix)
             VALUES ('root-profile', 'root', ?)",
        )
        .bind(now)
        .execute(&state.pool)
        .await
        .unwrap();
        let (_, session_token, _) =
            crate::profiles::create_identity_session(&state.pool, "root-profile")
                .await
                .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("vapor_identity_session={session_token}")).unwrap(),
        );
        headers.insert("origin", HeaderValue::from_static("https://vapor.example"));
        headers
    }

    #[test]
    fn generic_credentials_exclude_ssh_access_request_scope() {
        let scopes = normalize_scopes(&[
            "identity:role-request:create".to_string(),
            "platform:deploy-request:create".to_string(),
        ])
        .unwrap();

        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&CredentialScope::IdentityRoleRequestCreate));
        assert!(scopes.contains(&CredentialScope::PlatformDeployRequestCreate));
        assert!(normalize_scopes(&["platform:ssh-access:request".to_string()]).is_err());
    }

    #[test]
    fn rejects_unknown_or_empty_scope_sets() {
        assert!(normalize_scopes(&["root".to_string()]).is_err());
        assert!(normalize_scopes(&[]).is_err());
    }

    #[test]
    fn hashes_credentials_without_retaining_the_secret() {
        assert_eq!(
            credential_digest("vap_req_example"),
            "7be462ec75ae30879478cfb136fb8618061ef09a58d0b2725d898e690f3dd8d1"
        );
    }

    #[tokio::test]
    async fn internal_verification_requires_the_platform_service_credential() {
        let state = test_state().await;
        let response = verify_automation_credential(
            State(state),
            HeaderMap::new(),
            Json(VerifyAutomationCredentialRequest {
                audience: "vapor-platform-server".to_string(),
                scope: "platform:deploy-request:create".to_string(),
                credential_token: REQUEST_TOKEN.to_string(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verifies_only_active_credentials_with_the_requested_scope() {
        let state = test_state().await;
        insert_credential(&state, crate::util::unix_now_i64() + 3600, None).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {SERVICE_TOKEN}")).unwrap(),
        );
        let response = verify_automation_credential(
            State(state.clone()),
            headers.clone(),
            Json(VerifyAutomationCredentialRequest {
                audience: "vapor-platform-server".to_string(),
                scope: "platform:deploy-request:create".to_string(),
                credential_token: REQUEST_TOKEN.to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let wrong_scope = verify_automation_credential(
            State(state.clone()),
            headers.clone(),
            Json(VerifyAutomationCredentialRequest {
                audience: "vapor-identity-server".to_string(),
                scope: "identity:role-request:create".to_string(),
                credential_token: REQUEST_TOKEN.to_string(),
            }),
        )
        .await;
        assert_eq!(wrong_scope.status(), StatusCode::UNAUTHORIZED);

        let wrong_audience = verify_automation_credential(
            State(state),
            headers,
            Json(VerifyAutomationCredentialRequest {
                audience: "some-other-service".to_string(),
                scope: "platform:deploy-request:create".to_string(),
                credential_token: REQUEST_TOKEN.to_string(),
            }),
        )
        .await;
        assert_eq!(wrong_audience.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn refuses_expired_and_revoked_request_credentials() {
        let expired = test_state().await;
        insert_credential(&expired, crate::util::unix_now_i64() - 1, None).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {SERVICE_TOKEN}")).unwrap(),
        );
        let request = || {
            Json(VerifyAutomationCredentialRequest {
                audience: "vapor-platform-server".to_string(),
                scope: "platform:deploy-request:create".to_string(),
                credential_token: REQUEST_TOKEN.to_string(),
            })
        };
        let expired_response =
            verify_automation_credential(State(expired), headers.clone(), request()).await;
        assert_eq!(expired_response.status(), StatusCode::UNAUTHORIZED);

        let revoked = test_state().await;
        insert_credential(
            &revoked,
            crate::util::unix_now_i64() + 3600,
            Some(crate::util::unix_now_i64()),
        )
        .await;
        let revoked_response =
            verify_automation_credential(State(revoked), headers, request()).await;
        assert_eq!(revoked_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn root_can_issue_list_and_revoke_request_only_credentials() {
        let state = test_state().await;
        let headers = root_headers(&state).await;
        let response = super::create_automation_credential(
            State(state.clone()),
            headers.clone(),
            Json(super::CreateAutomationCredentialRequest {
                label: "GitHub deployment workflow".to_string(),
                expires_at_unix: crate::util::unix_now_i64() + 86_400,
                scopes: vec!["platform:deploy-request:create".to_string()],
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = created["id"].as_str().unwrap().to_string();
        let token = created["bearer_token"].as_str().unwrap();
        assert_eq!(token.len(), 72);
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT token_hash FROM automation_credentials WHERE id = ?"
            )
            .bind(&id)
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            credential_digest(token)
        );

        let listed =
            super::list_automation_credentials(State(state.clone()), headers.clone()).await;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed_body = to_bytes(listed.into_body(), 4096).await.unwrap();
        let listed_json: serde_json::Value = serde_json::from_slice(&listed_body).unwrap();
        assert!(!listed_json.to_string().contains(token));
        assert!(listed_json
            .to_string()
            .contains("platform:deploy-request:create"));

        let revoked = super::revoke_automation_credential(
            State(state.clone()),
            headers,
            axum::extract::Path(id),
        )
        .await;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events WHERE event_type = 'automation_credential_revoked'")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn credential_issuance_rejects_cross_origin_and_unknown_scope() {
        let state = test_state().await;
        let mut headers = root_headers(&state).await;
        headers.insert(
            "origin",
            HeaderValue::from_static("https://attacker.example"),
        );
        let request = || {
            Json(super::CreateAutomationCredentialRequest {
                label: "automation".to_string(),
                expires_at_unix: crate::util::unix_now_i64() + 86_400,
                scopes: vec!["root".to_string()],
            })
        };
        let cross_origin =
            super::create_automation_credential(State(state.clone()), headers.clone(), request())
                .await;
        assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);

        headers.insert("origin", HeaderValue::from_static("https://vapor.example"));
        let unknown_scope =
            super::create_automation_credential(State(state.clone()), headers, request()).await;
        assert_eq!(unknown_scope.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM automation_credentials")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            0
        );
    }
}

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::profiles::current_profile_from_headers;
use crate::types::AppState;
use crate::util::{same_origin_browser_request, unix_now_i64};

const MIN_CREDENTIAL_TTL_SECONDS: i64 = 3600;
const MAX_CREDENTIAL_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CredentialScope {
    IdentityRoleRequestCreate,
    PlatformDeployRequestCreate,
    PlatformSshAccessRequestCreate,
}

impl CredentialScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::IdentityRoleRequestCreate => "identity:role-request:create",
            Self::PlatformDeployRequestCreate => "platform:deploy-request:create",
            Self::PlatformSshAccessRequestCreate => "platform:ssh-access:request",
        }
    }
}

fn normalize_scopes(values: &[String]) -> Result<BTreeSet<CredentialScope>, ()> {
    if values.is_empty() || values.len() > 3 {
        return Err(());
    }

    let mut scopes = BTreeSet::new();
    for value in values {
        let scope = match value.as_str() {
            "identity:role-request:create" => CredentialScope::IdentityRoleRequestCreate,
            "platform:deploy-request:create" => CredentialScope::PlatformDeployRequestCreate,
            _ => return Err(()),
        };
        if !scopes.insert(scope) {
            return Err(());
        }
    }
    Ok(scopes)
}

pub(crate) fn credential_digest(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) struct RequestCredentialPrincipal {
    pub(crate) credential_id: String,
    pub(crate) actor_profile_id: String,
    pub(crate) bound_ssh_fingerprint: Option<String>,
    pub(crate) bound_ssh_request_hash: Option<String>,
}

pub(crate) fn valid_request_token_format(token: &str) -> bool {
    token.len() == 72
        && token
            .strip_prefix("vap_req_")
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub(crate) async fn request_credential_principal(
    pool: &sqlx::SqlitePool,
    token: &str,
    required_scope: CredentialScope,
) -> Result<Option<RequestCredentialPrincipal>, sqlx::Error> {
    if !valid_request_token_format(token) {
        return Ok(None);
    }
    let now = unix_now_i64();
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT c.id, c.created_by_profile_id, c.scopes, c.single_use, c.use_count,
                c.bound_ssh_fingerprint, c.bound_ssh_request_hash
         FROM automation_credentials c
         JOIN profiles p ON p.id = c.created_by_profile_id
         WHERE c.token_hash = ? AND c.expires_at_unix > ? AND c.revoked_at_unix IS NULL
           AND p.disabled_at_unix IS NULL",
    )
    .bind(credential_digest(token))
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let scope_storage: String = row.get("scopes");
    if !scope_storage
        .split_whitespace()
        .any(|scope| scope == required_scope.as_str())
    {
        return Ok(None);
    }
    let credential_id: String = row.get("id");
    let single_use: i64 = row.get("single_use");
    let use_count: i64 = row.get("use_count");
    let bound_ssh_fingerprint: Option<String> = row.get("bound_ssh_fingerprint");
    let bound_ssh_request_hash: Option<String> = row.get("bound_ssh_request_hash");
    if required_scope == CredentialScope::PlatformSshAccessRequestCreate
        && (single_use == 0 || bound_ssh_fingerprint.is_none() || bound_ssh_request_hash.is_none())
    {
        return Ok(None);
    }
    if single_use != 0 {
        if use_count != 0 {
            return Ok(None);
        }
        let consumed = sqlx::query(
            "UPDATE automation_credentials SET use_count = 1
             WHERE id = ? AND single_use = 1 AND use_count = 0
               AND expires_at_unix > ? AND revoked_at_unix IS NULL",
        )
        .bind(&credential_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if consumed.rows_affected() != 1 {
            return Ok(None);
        }
    }
    let principal = RequestCredentialPrincipal {
        credential_id,
        actor_profile_id: row.get("created_by_profile_id"),
        bound_ssh_fingerprint,
        bound_ssh_request_hash,
    };
    tx.commit().await?;
    Ok(Some(principal))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateAutomationCredentialRequest {
    pub(crate) label: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) scopes: Vec<String>,
}

#[derive(Serialize)]
struct CreatedAutomationCredential {
    id: String,
    label: String,
    bearer_token: String,
    scopes: Vec<&'static str>,
    created_at_unix: i64,
    expires_at_unix: i64,
}

#[derive(Serialize)]
struct AutomationCredentialSummary {
    id: String,
    label: String,
    scopes: Vec<String>,
    created_at_unix: i64,
    expires_at_unix: i64,
    revoked_at_unix: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyAutomationCredentialRequest {
    pub(crate) audience: String,
    pub(crate) scope: String,
    pub(crate) credential_token: String,
}

#[derive(Serialize)]
pub(crate) struct VerifiedAutomationCredential {
    pub(crate) credential_id: String,
    pub(crate) actor_profile_id: String,
    pub(crate) scope: String,
    pub(crate) bound_ssh_fingerprint: Option<String>,
    pub(crate) bound_ssh_request_hash: Option<String>,
}

pub(crate) async fn create_automation_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAutomationCredentialRequest>,
) -> Response {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) if current.root_authorized => current,
        Ok(Some(_)) => return (StatusCode::FORBIDDEN, "root role required\n").into_response(),
        Ok(None) => return (StatusCode::UNAUTHORIZED, "root session required\n").into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }

    let label = request.label.trim();
    if label.is_empty() || label.len() > 80 || label.chars().any(char::is_control) {
        return (StatusCode::BAD_REQUEST, "invalid credential label\n").into_response();
    }
    let scopes = match normalize_scopes(&request.scopes) {
        Ok(scopes) => scopes,
        Err(()) => return (StatusCode::BAD_REQUEST, "invalid credential scopes\n").into_response(),
    };
    let now = unix_now_i64();
    if request.expires_at_unix < now + MIN_CREDENTIAL_TTL_SECONDS
        || request.expires_at_unix > now + MAX_CREDENTIAL_TTL_SECONDS
    {
        return (
            StatusCode::BAD_REQUEST,
            "credential expiry must be 1 hour to 90 days\n",
        )
            .into_response();
    }

    let id = Uuid::new_v4().to_string();
    let token = format!(
        "vap_req_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let digest = credential_digest(&token);
    let scope_values = scopes
        .iter()
        .map(|scope| scope.as_str())
        .collect::<Vec<_>>();
    let scope_storage = scope_values.join(" ");
    let inserted = sqlx::query(
        "INSERT INTO automation_credentials
         (id, token_hash, label, scopes, created_by_profile_id, created_at_unix, expires_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(digest)
    .bind(label)
    .bind(&scope_storage)
    .bind(&current.profile_id)
    .bind(now)
    .bind(request.expires_at_unix)
    .execute(&state.pool)
    .await;
    if inserted.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let detail = format!(
        "label={label};scopes={scope_storage};expires_at_unix={}",
        request.expires_at_unix
    );
    if sqlx::query(
        "INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail)
         VALUES ('automation_credential_created', ?, NULL, ?, ?)",
    )
    .bind(&current.profile_id)
    .bind(now)
    .bind(detail)
    .execute(&state.pool)
    .await
    .is_err()
    {
        let _ = sqlx::query("DELETE FROM automation_credentials WHERE id = ?")
            .bind(&id)
            .execute(&state.pool)
            .await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    (
        StatusCode::CREATED,
        Json(CreatedAutomationCredential {
            id,
            label: label.to_string(),
            bearer_token: token,
            scopes: scope_values,
            created_at_unix: now,
            expires_at_unix: request.expires_at_unix,
        }),
    )
        .into_response()
}

pub(crate) async fn list_automation_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) if current.root_authorized => current,
        Ok(Some(_)) => return (StatusCode::FORBIDDEN, "root role required\n").into_response(),
        Ok(None) => return (StatusCode::UNAUTHORIZED, "root session required\n").into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let _ = current;
    let rows = match sqlx::query(
        "SELECT id, label, scopes, created_at_unix, expires_at_unix, revoked_at_unix
         FROM automation_credentials ORDER BY created_at_unix DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let credentials = rows
        .iter()
        .map(|row| {
            let scope_storage: String = row.get("scopes");
            AutomationCredentialSummary {
                id: row.get("id"),
                label: row.get("label"),
                scopes: scope_storage
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
                created_at_unix: row.get("created_at_unix"),
                expires_at_unix: row.get("expires_at_unix"),
                revoked_at_unix: row.get("revoked_at_unix"),
            }
        })
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(credentials)).into_response()
}

pub(crate) async fn revoke_automation_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) if current.root_authorized => current,
        Ok(Some(_)) => return (StatusCode::FORBIDDEN, "root role required\n").into_response(),
        Ok(None) => return (StatusCode::UNAUTHORIZED, "root session required\n").into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if !same_origin_browser_request(&headers, &state.config) {
        return (StatusCode::FORBIDDEN, "same-origin request required\n").into_response();
    }
    if Uuid::parse_str(&id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let now = unix_now_i64();
    let result = sqlx::query(
        "UPDATE automation_credentials SET revoked_at_unix = ?
         WHERE id = ? AND revoked_at_unix IS NULL",
    )
    .bind(now)
    .bind(&id)
    .execute(&state.pool)
    .await;
    let Ok(result) = result else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if result.rows_affected() == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }
    if sqlx::query(
        "INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail)
         VALUES ('automation_credential_revoked', ?, NULL, ?, ?)",
    )
    .bind(&current.profile_id)
    .bind(now)
    .bind(format!("credential_id={id}"))
    .execute(&state.pool)
    .await
    .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn verify_automation_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VerifyAutomationCredentialRequest>,
) -> Response {
    let Some(service_token) = state.platform_request_authz_token.as_deref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !crate::util::authorization_service_authorized(&headers, Some(service_token)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let expected_scope = match (request.audience.as_str(), request.scope.as_str()) {
        ("vapor-platform-server", "platform:deploy-request:create") => {
            CredentialScope::PlatformDeployRequestCreate
        }
        ("vapor-platform-server", "platform:ssh-access:request") => {
            CredentialScope::PlatformSshAccessRequestCreate
        }
        ("vapor-identity-server", "identity:role-request:create") => {
            CredentialScope::IdentityRoleRequestCreate
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    if request.scope != expected_scope.as_str() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let principal =
        match request_credential_principal(&state.pool, &request.credential_token, expected_scope)
            .await
        {
            Ok(Some(principal)) => principal,
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
    (
        StatusCode::OK,
        Json(VerifiedAutomationCredential {
            credential_id: principal.credential_id,
            actor_profile_id: principal.actor_profile_id,
            scope: request.scope,
            bound_ssh_fingerprint: principal.bound_ssh_fingerprint,
            bound_ssh_request_hash: principal.bound_ssh_request_hash,
        }),
    )
        .into_response()
}
