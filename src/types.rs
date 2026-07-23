use crate::config::AuthConfig;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pool: SqlitePool,
    pub(crate) db_path: Arc<PathBuf>,
    pub(crate) admin_token: Option<String>,
    pub(crate) config: Arc<AuthConfig>,
    pub(crate) http: reqwest::Client,
}

#[derive(Deserialize)]
pub(crate) struct SteamTicketRequest {
    pub(crate) ticket_hex: String,
    pub(crate) identity: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct GitHubTokenRequest {
    pub(crate) access_token: String,
}

#[derive(Deserialize)]
pub(crate) struct GitHubCallbackQuery {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct StartAuthAttemptRequest {
    pub(crate) purpose: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct StartAuthAttemptResponse {
    pub(crate) auth_attempt_id: String,
    pub(crate) purpose: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) expires_in_seconds: i64,
    pub(crate) steam_required: bool,
    pub(crate) github_required: bool,
    pub(crate) dashboard_session_ttl_seconds: i64,
}

#[derive(Deserialize)]
pub(crate) struct SteamSessionTicketRequest {
    pub(crate) auth_attempt_id: String,
    pub(crate) ticket_hex: String,
    pub(crate) identity: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct GitHubSessionTokenRequest {
    pub(crate) auth_attempt_id: String,
    pub(crate) access_token: String,
}

#[derive(Deserialize)]
pub(crate) struct GitHubDeviceStartRequest {
    pub(crate) auth_attempt_id: String,
}

#[derive(Serialize)]
pub(crate) struct GitHubDeviceStartResponse {
    pub(crate) auth_attempt_id: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    pub(crate) verification_uri_complete: Option<String>,
    pub(crate) expires_at_unix: i64,
    pub(crate) poll_interval_seconds: i64,
}

#[derive(Deserialize)]
pub(crate) struct GitHubDevicePollRequest {
    pub(crate) auth_attempt_id: String,
}

#[derive(Serialize)]
pub(crate) struct GitHubDevicePollResponse {
    pub(crate) auth_attempt_id: String,
    pub(crate) status: &'static str,
    pub(crate) github_login: Option<String>,
    pub(crate) github_user_id: Option<i64>,
    pub(crate) next_poll_at_unix: Option<i64>,
    pub(crate) poll_interval_seconds: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct FinishAuthAttemptRequest {
    pub(crate) auth_attempt_id: String,
    pub(crate) bootstrap_first_root: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct FinishAuthAttemptResponse {
    pub(crate) session_id: String,
    pub(crate) profile_id: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) root_authorized: bool,
    pub(crate) roles: Vec<String>,
    pub(crate) steam_id64: String,
    pub(crate) github_login: String,
}

#[derive(Deserialize)]
pub(crate) struct GrantRootRequest {
    pub(crate) profile_id: String,
}

#[derive(Serialize)]
pub(crate) struct GrantRootResponse {
    pub(crate) profile_id: String,
    pub(crate) role: &'static str,
    pub(crate) granted: bool,
}

#[derive(Deserialize)]
pub(crate) struct GitHubUser {
    pub(crate) id: i64,
    pub(crate) login: String,
    pub(crate) name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct GitHubDeviceCodeResponse {
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    pub(crate) verification_uri_complete: Option<String>,
    pub(crate) expires_in: i64,
    pub(crate) interval: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct GitHubAccessTokenResponse {
    pub(crate) access_token: Option<String>,
    pub(crate) token_type: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) interval: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct AuthStatus {
    pub(crate) service: &'static str,
    pub(crate) database: &'static str,
    pub(crate) steam_app_id: u32,
    pub(crate) steam_identity_ready: bool,
    pub(crate) steam_auth_identity: String,
    pub(crate) github_identity_ready: bool,
    pub(crate) github_client_id_configured: bool,
    pub(crate) github_browser_login_ready: bool,
    pub(crate) github_client_secret_configured: bool,
    pub(crate) steam_browser_login_ready: bool,
    pub(crate) dashboard_ready: bool,
    pub(crate) dashboard_basic_password_configured: bool,
    pub(crate) dashboard_session_ttl_seconds: i64,
}

#[derive(Serialize)]
pub(crate) struct IdentityAuthResponse {
    pub(crate) profile_id: String,
    pub(crate) provider: &'static str,
    pub(crate) steam_id64: Option<String>,
    pub(crate) github_user_id: Option<i64>,
    pub(crate) github_login: Option<String>,
}
