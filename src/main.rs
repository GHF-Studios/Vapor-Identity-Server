use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::net::TcpListener;
use uuid::Uuid;

const DEFAULT_BIND: &str = "127.0.0.1:7113";
const DEFAULT_STATE_DIR: &str = "state/identity";
const DEFAULT_DB_NAME: &str = "identity.sqlite3";
const DEFAULT_STEAM_APP_ID: u32 = 2_122_620;
const DEFAULT_STEAM_AUTH_IDENTITY: &str = "vapor-identity";
const MAX_AUTH_BODY_BYTES: usize = 16 * 1024;
const AUTH_ATTEMPT_TTL_SECONDS: i64 = 5 * 60;
const DASHBOARD_SESSION_TTL_SECONDS: i64 = 5 * 60;
const SESSION_COOKIE: &str = "vapor_identity_session";

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    db_path: Arc<PathBuf>,
    admin_token: Option<String>,
    config: Arc<AuthConfig>,
    http: reqwest::Client,
}

#[derive(Clone)]
struct AuthConfig {
    steam_app_id: u32,
    steam_auth_identity: String,
    steam_web_api_key: Option<String>,
    github_client_id: Option<String>,
    dashboard_password: Option<String>,
    cookie_secure: bool,
    cookie_path: String,
}

#[derive(Deserialize)]
struct SteamTicketRequest {
    ticket_hex: String,
    identity: Option<String>,
}

#[derive(Deserialize)]
struct GitHubTokenRequest {
    access_token: String,
}

#[derive(Deserialize)]
struct StartAuthAttemptRequest {
    purpose: Option<String>,
}

#[derive(Serialize)]
struct StartAuthAttemptResponse {
    auth_attempt_id: String,
    purpose: String,
    expires_at_unix: i64,
    expires_in_seconds: i64,
    steam_required: bool,
    github_required: bool,
    dashboard_session_ttl_seconds: i64,
}

#[derive(Deserialize)]
struct SteamSessionTicketRequest {
    auth_attempt_id: String,
    ticket_hex: String,
    identity: Option<String>,
}

#[derive(Deserialize)]
struct GitHubSessionTokenRequest {
    auth_attempt_id: String,
    access_token: String,
}

#[derive(Deserialize)]
struct GitHubDeviceStartRequest {
    auth_attempt_id: String,
}

#[derive(Serialize)]
struct GitHubDeviceStartResponse {
    auth_attempt_id: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_at_unix: i64,
    poll_interval_seconds: i64,
}

#[derive(Deserialize)]
struct GitHubDevicePollRequest {
    auth_attempt_id: String,
}

#[derive(Serialize)]
struct GitHubDevicePollResponse {
    auth_attempt_id: String,
    status: &'static str,
    github_login: Option<String>,
    github_user_id: Option<i64>,
    next_poll_at_unix: Option<i64>,
    poll_interval_seconds: Option<i64>,
}

#[derive(Deserialize)]
struct FinishAuthAttemptRequest {
    auth_attempt_id: String,
    bootstrap_first_root: Option<bool>,
}

#[derive(Serialize)]
struct FinishAuthAttemptResponse {
    session_id: String,
    profile_id: String,
    expires_at_unix: i64,
    root_authorized: bool,
    roles: Vec<String>,
    steam_id64: String,
    github_login: String,
}

#[derive(Deserialize)]
struct GrantRootRequest {
    profile_id: String,
}

#[derive(Serialize)]
struct GrantRootResponse {
    profile_id: String,
    role: &'static str,
    granted: bool,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GitHubDeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: i64,
    interval: Option<i64>,
}

#[derive(Deserialize)]
struct GitHubAccessTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    error: Option<String>,
    interval: Option<i64>,
}

#[derive(Serialize)]
struct AuthStatus {
    service: &'static str,
    database: &'static str,
    steam_app_id: u32,
    steam_identity_ready: bool,
    steam_auth_identity: String,
    github_identity_ready: bool,
    github_client_id_configured: bool,
    dashboard_ready: bool,
    dashboard_basic_password_configured: bool,
    dashboard_session_ttl_seconds: i64,
}

#[derive(Serialize)]
struct IdentityAuthResponse {
    profile_id: String,
    provider: &'static str,
    steam_id64: Option<String>,
    github_user_id: Option<i64>,
    github_login: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("VAPOR_IDENTITY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let state_dir = PathBuf::from(
        env::var("VAPOR_IDENTITY_STATE").unwrap_or_else(|_| DEFAULT_STATE_DIR.into()),
    );
    fs::create_dir_all(&state_dir).await?;
    let db_path = env::var("VAPOR_IDENTITY_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| state_dir.join(DEFAULT_DB_NAME));
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let pool = open_database(&db_path).await?;
    run_migrations(&pool).await?;
    let config = Arc::new(read_auth_config());
    let http = reqwest::Client::builder()
        .user_agent("Vapor-Identity-Server/0.1")
        .build()?;

    let state = AppState {
        pool,
        db_path: Arc::new(db_path),
        admin_token: env::var("VAPOR_IDENTITY_ADMIN_TOKEN")
            .ok()
            .filter(|value| !value.is_empty()),
        config,
        http,
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/v1/auth/status", get(auth_status))
        .route("/v1/auth/session/start", post(start_auth_attempt))
        .route(
            "/v1/auth/session/steam/ticket",
            post(auth_session_steam_ticket),
        )
        .route(
            "/v1/auth/session/github/token",
            post(auth_session_github_token),
        )
        .route(
            "/v1/auth/session/github/device/start",
            post(auth_session_github_device_start),
        )
        .route(
            "/v1/auth/session/github/device/poll",
            post(auth_session_github_device_poll),
        )
        .route("/v1/auth/session/finish", post(finish_auth_attempt))
        .route("/v1/auth/steam/ticket", post(auth_steam_ticket))
        .route("/v1/auth/github/token", post(auth_github_token))
        .route("/v1/admin/profiles", get(list_profiles))
        .route("/v1/admin/root/grant", post(grant_root_role))
        .route("/v1/init", post(init))
        .route("/v1/export", get(export_identity))
        .route("/admin", get(admin_dashboard))
        .route("/admin/", get(admin_dashboard))
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
        .with_state(state);

    let listener = TcpListener::bind(&bind).await?;
    eprintln!("vapor-identity-server listening on {bind}");
    axum::serve(listener, app).await?;

    Ok(())
}

fn read_auth_config() -> AuthConfig {
    AuthConfig {
        steam_app_id: env::var("VAPOR_IDENTITY_STEAM_APP_ID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(DEFAULT_STEAM_APP_ID),
        steam_auth_identity: env::var("VAPOR_IDENTITY_STEAM_AUTH_IDENTITY")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_STEAM_AUTH_IDENTITY.to_string()),
        steam_web_api_key: env::var("VAPOR_IDENTITY_STEAM_WEB_API_KEY")
            .ok()
            .filter(|value| !value.is_empty()),
        github_client_id: env::var("VAPOR_IDENTITY_GITHUB_CLIENT_ID")
            .ok()
            .filter(|value| !value.is_empty()),
        dashboard_password: env::var("VAPOR_IDENTITY_DASHBOARD_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty()),
        cookie_secure: env::var("VAPOR_IDENTITY_COOKIE_SECURE")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on")),
        cookie_path: env::var("VAPOR_IDENTITY_COOKIE_PATH")
            .ok()
            .filter(|value| {
                value.starts_with('/')
                    && !value.contains(';')
                    && !value.contains('\r')
                    && !value.contains('\n')
            })
            .unwrap_or_else(|| "/api/identity".to_string()),
    }
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let initialized = match is_initialized(&state.pool).await {
        Ok(initialized) => initialized,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to read initialization state: {error}\n"),
            );
        }
    };
    let schema_version = match schema_version(&state.pool).await {
        Ok(version) => version,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to read schema version: {error}\n"),
            );
        }
    };
    let body = format!(
        "service = \"vapor-identity-server\"\ndatabase = \"sqlite\"\nschema_version = {schema_version}\ninitialized = {initialized}\nsteam_identity_ready = {}\ngithub_identity_ready = {}\ndashboard_ready = {}\ndashboard_session_ttl_seconds = {DASHBOARD_SESSION_TTL_SECONDS}\n",
        state.config.steam_web_api_key.is_some(),
        state.config.github_client_id.is_some(),
        dashboard_identity_ready(&state.config)
    );
    (StatusCode::OK, body)
}

async fn auth_status(State(state): State<AppState>) -> Json<AuthStatus> {
    Json(AuthStatus {
        service: "vapor-identity-server",
        database: "sqlite",
        steam_app_id: state.config.steam_app_id,
        steam_identity_ready: state.config.steam_web_api_key.is_some(),
        steam_auth_identity: state.config.steam_auth_identity.clone(),
        github_identity_ready: state.config.github_client_id.is_some(),
        github_client_id_configured: state.config.github_client_id.is_some(),
        dashboard_ready: dashboard_identity_ready(&state.config),
        dashboard_basic_password_configured: state.config.dashboard_password.is_some(),
        dashboard_session_ttl_seconds: DASHBOARD_SESSION_TTL_SECONDS,
    })
}

async fn start_auth_attempt(
    State(state): State<AppState>,
    Json(request): Json<StartAuthAttemptRequest>,
) -> Response {
    let purpose = request
        .purpose
        .as_deref()
        .unwrap_or("root-dashboard")
        .trim();
    if purpose != "root-dashboard" {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: unsupported auth attempt purpose",
        );
    }

    let now = unix_now_i64();
    let auth_attempt_id = new_auth_attempt_id();
    let expires_at_unix = now + AUTH_ATTEMPT_TTL_SECONDS;
    if let Err(error) =
        create_auth_attempt(&state.pool, &auth_attempt_id, purpose, now, expires_at_unix).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to create auth attempt: {error}"),
        );
    }

    (
        StatusCode::CREATED,
        Json(StartAuthAttemptResponse {
            auth_attempt_id,
            purpose: purpose.to_string(),
            expires_at_unix,
            expires_in_seconds: AUTH_ATTEMPT_TTL_SECONDS,
            steam_required: true,
            github_required: true,
            dashboard_session_ttl_seconds: DASHBOARD_SESSION_TTL_SECONDS,
        }),
    )
        .into_response()
}

async fn auth_session_steam_ticket(
    State(state): State<AppState>,
    Json(request): Json<SteamSessionTicketRequest>,
) -> Response {
    let Some(key) = state.config.steam_web_api_key.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: Steam Web API key is not configured",
        );
    };
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    match auth_attempt_is_active(&state.pool, &request.auth_attempt_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read auth attempt: {error}"),
            );
        }
    }
    if !valid_hex_ticket(&request.ticket_hex) {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: invalid Steam ticket hex",
        );
    }

    let identity = request
        .identity
        .as_deref()
        .unwrap_or(&state.config.steam_auth_identity);
    let steam_id64 = match verify_steam_ticket(
        &state.http,
        key,
        state.config.steam_app_id,
        identity,
        &request.ticket_hex,
    )
    .await
    {
        Ok(steam_id64) => steam_id64,
        Err(response) => return response,
    };

    if let Err(error) =
        record_auth_attempt_steam(&state.pool, &request.auth_attempt_id, &steam_id64).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record Steam proof: {error}"),
        );
    }

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id: String::new(),
            provider: "steam",
            steam_id64: Some(steam_id64),
            github_user_id: None,
            github_login: None,
        }),
    )
        .into_response()
}

async fn auth_session_github_token(
    State(state): State<AppState>,
    Json(request): Json<GitHubSessionTokenRequest>,
) -> Response {
    if !github_device_ready(&state.config) {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    }
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    match auth_attempt_is_active(&state.pool, &request.auth_attempt_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read auth attempt: {error}"),
            );
        }
    }
    if request.access_token.trim().is_empty() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: empty GitHub access token",
        );
    }

    let user = match verify_github_access_token(&state.http, request.access_token.trim()).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(error) =
        record_auth_attempt_github(&state.pool, &request.auth_attempt_id, &user).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record GitHub proof: {error}"),
        );
    }

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id: String::new(),
            provider: "github",
            steam_id64: None,
            github_user_id: Some(user.id),
            github_login: Some(user.login),
        }),
    )
        .into_response()
}

async fn auth_session_github_device_start(
    State(state): State<AppState>,
    Json(request): Json<GitHubDeviceStartRequest>,
) -> Response {
    let Some(client_id) = state.config.github_client_id.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    };
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    match auth_attempt_is_active(&state.pool, &request.auth_attempt_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read auth attempt: {error}"),
            );
        }
    }

    let response = match state
        .http
        .post("https://github.com/login/device/code")
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&[("client_id", client_id), ("scope", "read:user")])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub device-code request failed: {error}"),
            );
        }
    };
    if !response.status().is_success() {
        return text_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "identity: GitHub rejected device-code request with {}",
                response.status()
            ),
        );
    }
    let device = match response.json::<GitHubDeviceCodeResponse>().await {
        Ok(device) => device,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub device-code response: {error}"),
            );
        }
    };
    let now = unix_now_i64();
    let interval = device.interval.unwrap_or(5).max(5);
    let github_expires_at = now + device.expires_in.max(0);
    let expires_at_unix = github_expires_at.min(now + AUTH_ATTEMPT_TTL_SECONDS);
    if let Err(error) = record_github_device_flow(
        &state.pool,
        &request.auth_attempt_id,
        &device.device_code,
        interval,
        expires_at_unix,
        now + interval,
    )
    .await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record GitHub device flow: {error}"),
        );
    }

    (
        StatusCode::CREATED,
        Json(GitHubDeviceStartResponse {
            auth_attempt_id: request.auth_attempt_id,
            user_code: device.user_code,
            verification_uri: device.verification_uri,
            verification_uri_complete: device.verification_uri_complete,
            expires_at_unix,
            poll_interval_seconds: interval,
        }),
    )
        .into_response()
}

async fn auth_session_github_device_poll(
    State(state): State<AppState>,
    Json(request): Json<GitHubDevicePollRequest>,
) -> Response {
    let Some(client_id) = state.config.github_client_id.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    };
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    let Some(device) = (match github_device_flow(&state.pool, &request.auth_attempt_id).await {
        Ok(device) => device,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read GitHub device flow: {error}"),
            );
        }
    }) else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub device flow is missing or expired",
        );
    };
    let now = unix_now_i64();
    if now < device.next_poll_at_unix {
        return (
            StatusCode::TOO_EARLY,
            Json(GitHubDevicePollResponse {
                auth_attempt_id: request.auth_attempt_id,
                status: "pending",
                github_login: None,
                github_user_id: None,
                next_poll_at_unix: Some(device.next_poll_at_unix),
                poll_interval_seconds: Some(device.interval_seconds),
            }),
        )
            .into_response();
    }

    let response = match state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&[
            ("client_id", client_id),
            ("device_code", device.device_code.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub device poll failed: {error}"),
            );
        }
    };
    if !response.status().is_success() {
        return text_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "identity: GitHub rejected device poll with {}",
                response.status()
            ),
        );
    }
    let token_response = match response.json::<GitHubAccessTokenResponse>().await {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub device poll response: {error}"),
            );
        }
    };
    if let Some(error) = token_response.error.as_deref() {
        let interval = match error {
            "slow_down" => device.interval_seconds + 5,
            _ => token_response
                .interval
                .unwrap_or(device.interval_seconds)
                .max(5),
        };
        let next_poll_at_unix = now + interval;
        if let Err(error) = update_github_device_poll(
            &state.pool,
            &request.auth_attempt_id,
            interval,
            next_poll_at_unix,
        )
        .await
        {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to update GitHub device poll state: {error}"),
            );
        }
        let status = match error {
            "authorization_pending" | "slow_down" => "pending",
            "expired_token" | "token_expired" => "expired",
            "access_denied" => "denied",
            _ => "failed",
        };
        let code = match status {
            "pending" => StatusCode::ACCEPTED,
            "expired" => StatusCode::GONE,
            "denied" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_GATEWAY,
        };
        return (
            code,
            Json(GitHubDevicePollResponse {
                auth_attempt_id: request.auth_attempt_id,
                status,
                github_login: None,
                github_user_id: None,
                next_poll_at_unix: Some(next_poll_at_unix),
                poll_interval_seconds: Some(interval),
            }),
        )
            .into_response();
    }
    let Some(access_token) = token_response.access_token.as_deref() else {
        return text_response(
            StatusCode::BAD_GATEWAY,
            "identity: GitHub device poll did not return an access token",
        );
    };
    if token_response
        .token_type
        .as_deref()
        .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
    {
        return text_response(
            StatusCode::BAD_GATEWAY,
            "identity: GitHub device poll returned unsupported token type",
        );
    }
    let user = match verify_github_access_token(&state.http, access_token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(error) =
        record_auth_attempt_github(&state.pool, &request.auth_attempt_id, &user).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record GitHub proof: {error}"),
        );
    }
    if let Err(error) = clear_github_device_flow(&state.pool, &request.auth_attempt_id).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to clear GitHub device flow: {error}"),
        );
    }

    (
        StatusCode::OK,
        Json(GitHubDevicePollResponse {
            auth_attempt_id: request.auth_attempt_id,
            status: "authorized",
            github_login: Some(user.login),
            github_user_id: Some(user.id),
            next_poll_at_unix: None,
            poll_interval_seconds: None,
        }),
    )
        .into_response()
}

async fn finish_auth_attempt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FinishAuthAttemptRequest>,
) -> Response {
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    let linked = match link_verified_auth_attempt(&state.pool, &request.auth_attempt_id).await {
        Ok(linked) => linked,
        Err(AuthFinishError::InvalidAttempt) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(AuthFinishError::MissingSteam) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: auth attempt has no verified Steam proof",
            );
        }
        Err(AuthFinishError::MissingGitHub) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: auth attempt has no verified GitHub proof",
            );
        }
        Err(AuthFinishError::ConflictingProfiles) => {
            return text_response(
                StatusCode::CONFLICT,
                "identity: verified Steam and GitHub accounts belong to different profiles",
            );
        }
        Err(AuthFinishError::Database(error)) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to link verified identity: {error}"),
            );
        }
    };

    let mut has_root = match profile_has_root_role(&state.pool, &linked.profile_id).await {
        Ok(has_root) => has_root,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read profile roles: {error}"),
            );
        }
    };
    if !has_root
        && request.bootstrap_first_root.unwrap_or(false)
        && authorized(&headers, &state.admin_token)
    {
        match active_root_profile_count(&state.pool).await {
            Ok(0) => {
                if let Err(error) = grant_root(&state.pool, &linked.profile_id, None).await {
                    return text_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("identity: failed to bootstrap root role: {error}"),
                    );
                }
                has_root = true;
            }
            Ok(_) => {}
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to read root role state: {error}"),
                );
            }
        }
    }
    if !has_root {
        return text_response(
            StatusCode::FORBIDDEN,
            "identity: verified profile does not have root role",
        );
    }

    let (session_id, token, expires_at_unix) =
        match create_identity_session(&state.pool, &linked.profile_id).await {
            Ok(session) => session,
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to create dashboard session: {error}"),
                );
            }
        };
    if let Err(error) = consume_auth_attempt(&state.pool, &request.auth_attempt_id).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to consume auth attempt: {error}"),
        );
    }
    let roles = match active_roles(&state.pool, &linked.profile_id).await {
        Ok(roles) => roles,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read session roles: {error}"),
            );
        }
    };

    (
        StatusCode::OK,
        [(
            SET_COOKIE,
            session_cookie(&state.config, &token, DASHBOARD_SESSION_TTL_SECONDS),
        )],
        Json(FinishAuthAttemptResponse {
            session_id,
            profile_id: linked.profile_id,
            expires_at_unix,
            root_authorized: true,
            roles,
            steam_id64: linked.steam_id64,
            github_login: linked.github_login,
        }),
    )
        .into_response()
}

async fn init(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&headers, &state.admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin token\n".to_string(),
        );
    }

    let initialized = match is_initialized(&state.pool).await {
        Ok(initialized) => initialized,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to read initialization state: {error}\n"),
            );
        }
    };
    if initialized {
        return (
            StatusCode::CONFLICT,
            "identity database already initialized\n".to_string(),
        );
    }

    if let Err(error) = initialize_identity(&state.pool).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("identity: failed to initialize database: {error}\n"),
        );
    }

    (
        StatusCode::CREATED,
        "identity: database initialized\n".to_string(),
    )
}

async fn auth_steam_ticket(
    State(state): State<AppState>,
    Json(request): Json<SteamTicketRequest>,
) -> Response {
    let Some(key) = state.config.steam_web_api_key.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: Steam Web API key is not configured",
        );
    };
    if !valid_hex_ticket(&request.ticket_hex) {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: invalid Steam ticket hex",
        );
    }

    let identity = request
        .identity
        .as_deref()
        .unwrap_or(&state.config.steam_auth_identity);
    let app_id = state.config.steam_app_id.to_string();
    let response = match state
        .http
        .get("https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/")
        .query(&[
            ("key", key),
            ("appid", app_id.as_str()),
            ("ticket", request.ticket_hex.as_str()),
            ("identity", identity),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: Steam verification request failed: {error}"),
            );
        }
    };

    if !response.status().is_success() {
        return text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: Steam rejected ticket with {}", response.status()),
        );
    }

    let body = match response.json::<Value>().await {
        Ok(body) => body,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode Steam response: {error}"),
            );
        }
    };
    let Some(steam_id64) = steam_id_from_response(&body) else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam response did not contain a verified steamid",
        );
    };

    let profile_id = match link_steam_account(&state.pool, &steam_id64).await {
        Ok(profile_id) => profile_id,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to persist Steam identity: {error}"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id,
            provider: "steam",
            steam_id64: Some(steam_id64),
            github_user_id: None,
            github_login: None,
        }),
    )
        .into_response()
}

async fn auth_github_token(
    State(state): State<AppState>,
    Json(request): Json<GitHubTokenRequest>,
) -> Response {
    if state.config.github_client_id.is_none() {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    }
    if request.access_token.trim().is_empty() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: empty GitHub access token",
        );
    }

    let response = match state
        .http
        .get("https://api.github.com/user")
        .bearer_auth(request.access_token.trim())
        .header(ACCEPT, "application/vnd.github+json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub verification request failed: {error}"),
            );
        }
    };

    if !response.status().is_success() {
        return text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub rejected token with {}", response.status()),
        );
    }

    let user = match response.json::<GitHubUser>().await {
        Ok(user) => user,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub response: {error}"),
            );
        }
    };

    let display_name = user.name.as_deref().unwrap_or(&user.login);
    let profile_id = match link_github_account(&state.pool, &user, display_name).await {
        Ok(profile_id) => profile_id,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to persist GitHub identity: {error}"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id,
            provider: "github",
            steam_id64: None,
            github_user_id: Some(user.id),
            github_login: Some(user.login),
        }),
    )
        .into_response()
}

async fn export_identity(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match admin_or_root_authorized(&state, &headers).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                "missing or invalid admin token/root session\n".to_string(),
            );
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to validate authorization: {error}\n"),
            );
        }
    }

    let body = match export_identity_state(&state.pool, &state.db_path).await {
        Ok(body) => body,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to export database state: {error}\n"),
            );
        }
    };
    (StatusCode::OK, body)
}

async fn list_profiles(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match admin_or_root_authorized(&state, &headers).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                "missing or invalid admin token/root session\n".to_string(),
            );
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to validate authorization: {error}\n"),
            );
        }
    }

    let body = match profile_listing(&state.pool).await {
        Ok(body) => body,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to list profiles: {error}\n"),
            );
        }
    };
    (StatusCode::OK, body)
}

async fn grant_root_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<GrantRootRequest>,
) -> Response {
    if !authorized(&headers, &state.admin_token) {
        return text_response(StatusCode::UNAUTHORIZED, "missing or invalid admin token");
    }
    if !valid_profile_id(&request.profile_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid profile id");
    }
    match profile_has_dual_identity(&state.pool, &request.profile_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: root role requires linked Steam and GitHub identities",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate profile identity state: {error}"),
            );
        }
    }
    let granted = match grant_root(&state.pool, &request.profile_id, None).await {
        Ok(granted) => granted,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to grant root role: {error}"),
            );
        }
    };
    (
        StatusCode::OK,
        Json(GrantRootResponse {
            profile_id: request.profile_id,
            role: "root",
            granted,
        }),
    )
        .into_response()
}

async fn admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match root_session_profile_id(&state.pool, &headers).await {
        Ok(Some(_profile_id)) => {}
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Html(unauthenticated_dashboard_html(&state.config)),
            )
                .into_response();
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to validate dashboard session: {error}\n"),
            )
                .into_response();
        }
    }

    if !dashboard_identity_ready(&state.config) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Html(unconfigured_dashboard_html(&state.config)),
        )
            .into_response();
    }

    let profile_rows = match profile_rows(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to load dashboard: {error}\n"),
            )
                .into_response();
        }
    };
    let mut rows = String::new();
    for row in profile_rows {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&row.profile_id),
            html_escape(row.display_name.as_deref().unwrap_or("")),
            html_escape(row.steam_ids.as_deref().unwrap_or("")),
            html_escape(row.github_logins.as_deref().unwrap_or("")),
            html_escape(row.roles.as_deref().unwrap_or(""))
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"5\">No profiles yet.</td></tr>");
    }

    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Identity Admin</title>\
         <style>body{{max-width:1100px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem;text-align:left}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}</style>\
         <h1>Vapor Identity Admin</h1>\
         <p>Access requires a short-lived Vapor identity session for a root profile with linked Steam and GitHub identities.</p>\
         <h2>Readiness</h2>\
         <ul><li>Steam verification configured: <code>{}</code></li>\
         <li>GitHub client configured: <code>{}</code></li>\
         <li>Dashboard session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <h2>Profiles</h2><table><thead><tr><th>Profile</th><th>Name</th><th>Steam</th><th>GitHub</th><th>Roles</th></tr></thead><tbody>{rows}</tbody></table>",
        state.config.steam_web_api_key.is_some(),
        state.config.github_client_id.is_some()
    ))
    .into_response()
}

async fn open_database(db_path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(&pool)
        .await?;
    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at_unix INTEGER NOT NULL
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS service_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at_unix INTEGER NOT NULL
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            display_name TEXT,
            created_at_unix INTEGER NOT NULL,
            disabled_at_unix INTEGER
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS steam_accounts (
            steam_id64 TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            linked_at_unix INTEGER NOT NULL,
            verified_at_unix INTEGER NOT NULL
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS github_accounts (
            github_user_id INTEGER PRIMARY KEY,
            github_login TEXT NOT NULL UNIQUE,
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            linked_at_unix INTEGER NOT NULL,
            verified_at_unix INTEGER NOT NULL
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS profile_roles (
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('root', 'content-developer')),
            granted_at_unix INTEGER NOT NULL,
            revoked_at_unix INTEGER,
            PRIMARY KEY (profile_id, role)
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_profile_id TEXT REFERENCES profiles(id),
            subject_profile_id TEXT REFERENCES profiles(id),
            created_at_unix INTEGER NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS auth_attempts (
            id TEXT PRIMARY KEY,
            purpose TEXT NOT NULL CHECK (purpose IN ('root-dashboard')),
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            consumed_at_unix INTEGER,
            steam_id64 TEXT,
            steam_verified_at_unix INTEGER,
            github_user_id INTEGER,
            github_login TEXT,
            github_name TEXT,
            github_verified_at_unix INTEGER,
            github_device_code TEXT,
            github_device_interval_seconds INTEGER,
            github_device_expires_at_unix INTEGER,
            github_device_next_poll_at_unix INTEGER
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS identity_sessions (
            token_hash TEXT PRIMARY KEY,
            session_id TEXT NOT NULL UNIQUE,
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            revoked_at_unix INTEGER
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_auth_attempts_active
         ON auth_attempts (expires_at_unix, consumed_at_unix)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_identity_sessions_profile
         ON identity_sessions (profile_id, expires_at_unix, revoked_at_unix)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (1, 'initial_identity_schema', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (2, 'auth_attempts_and_sessions', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn initialize_identity(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let now = unix_now_i64();
    let mut tx = pool.begin().await?;
    for (key, value) in [
        ("initialized_at_unix", now.to_string()),
        ("policy_players_require_github", "false".to_string()),
        ("policy_developers_require_steam", "true".to_string()),
        ("policy_developers_require_github", "true".to_string()),
        ("policy_root_requires_role", "true".to_string()),
    ] {
        sqlx::query(
            "INSERT INTO service_metadata (key, value, updated_at_unix)
             VALUES (?, ?, ?)",
        )
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn is_initialized(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT value FROM service_metadata WHERE key = 'initialized_at_unix'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(value.is_some())
}

async fn schema_version(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let version =
        sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(version) FROM schema_migrations")
            .fetch_one(pool)
            .await?;
    Ok(version.unwrap_or(0))
}

async fn export_identity_state(pool: &SqlitePool, db_path: &Path) -> Result<String, sqlx::Error> {
    let schema_version = schema_version(pool).await?;
    let initialized = is_initialized(pool).await?;
    let metadata = sqlx::query("SELECT key, value FROM service_metadata ORDER BY key")
        .fetch_all(pool)
        .await?;
    let profile_count = count_rows(pool, "profiles").await?;
    let steam_account_count = count_rows(pool, "steam_accounts").await?;
    let github_account_count = count_rows(pool, "github_accounts").await?;
    let role_count = count_rows(pool, "profile_roles").await?;
    let audit_event_count = count_rows(pool, "audit_events").await?;
    let auth_attempt_count = count_rows(pool, "auth_attempts").await?;
    let session_count = count_rows(pool, "identity_sessions").await?;

    let mut body = String::new();
    body.push_str("database = \"sqlite\"\n");
    body.push_str(&format!(
        "database_path = {}\n",
        toml_string(&db_path.display().to_string())
    ));
    body.push_str(&format!("schema_version = {schema_version}\n"));
    body.push_str(&format!("initialized = {initialized}\n"));
    body.push_str("\n[metadata]\n");
    if metadata.is_empty() {
        body.push_str("# identity database has no service metadata yet\n");
    } else {
        for row in metadata {
            let key: String = row.get("key");
            let value: String = row.get("value");
            body.push_str(&format!("{key} = {}\n", toml_string(&value)));
        }
    }
    body.push_str("\n[counts]\n");
    body.push_str(&format!("profiles = {profile_count}\n"));
    body.push_str(&format!("steam_accounts = {steam_account_count}\n"));
    body.push_str(&format!("github_accounts = {github_account_count}\n"));
    body.push_str(&format!("profile_roles = {role_count}\n"));
    body.push_str(&format!("audit_events = {audit_event_count}\n"));
    body.push_str(&format!("auth_attempts = {auth_attempt_count}\n"));
    body.push_str(&format!("identity_sessions = {session_count}\n"));
    Ok(body)
}

async fn count_rows(pool: &SqlitePool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = match table {
        "profiles" => "SELECT COUNT(*) FROM profiles",
        "steam_accounts" => "SELECT COUNT(*) FROM steam_accounts",
        "github_accounts" => "SELECT COUNT(*) FROM github_accounts",
        "profile_roles" => "SELECT COUNT(*) FROM profile_roles",
        "audit_events" => "SELECT COUNT(*) FROM audit_events",
        "auth_attempts" => "SELECT COUNT(*) FROM auth_attempts",
        "identity_sessions" => "SELECT COUNT(*) FROM identity_sessions",
        _ => unreachable!("table name is constrained by caller"),
    };
    sqlx::query_scalar(sql).fetch_one(pool).await
}

async fn create_auth_attempt(
    pool: &SqlitePool,
    id: &str,
    purpose: &str,
    now: i64,
    expires_at_unix: i64,
) -> Result<(), sqlx::Error> {
    prune_expired_auth_state(pool, now).await?;
    sqlx::query(
        "INSERT INTO auth_attempts (id, purpose, created_at_unix, expires_at_unix)
         VALUES (?, ?, ?, ?)",
    )
    .bind(id)
    .bind(purpose)
    .bind(now)
    .bind(expires_at_unix)
    .execute(pool)
    .await?;
    Ok(())
}

async fn prune_expired_auth_state(pool: &SqlitePool, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM auth_attempts WHERE expires_at_unix <= ? OR consumed_at_unix IS NOT NULL",
    )
    .bind(now)
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE identity_sessions
         SET revoked_at_unix = COALESCE(revoked_at_unix, ?)
         WHERE expires_at_unix <= ? AND revoked_at_unix IS NULL",
    )
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn auth_attempt_is_active(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let now = unix_now_i64();
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS (
            SELECT 1 FROM auth_attempts
            WHERE id = ?
              AND expires_at_unix > ?
              AND consumed_at_unix IS NULL
        )",
    )
    .bind(id)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(exists == 1)
}

async fn record_auth_attempt_steam(
    pool: &SqlitePool,
    id: &str,
    steam_id64: &str,
) -> Result<(), sqlx::Error> {
    let now = unix_now_i64();
    sqlx::query(
        "UPDATE auth_attempts
         SET steam_id64 = ?, steam_verified_at_unix = ?
         WHERE id = ? AND expires_at_unix > ? AND consumed_at_unix IS NULL",
    )
    .bind(steam_id64)
    .bind(now)
    .bind(id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn record_auth_attempt_github(
    pool: &SqlitePool,
    id: &str,
    user: &GitHubUser,
) -> Result<(), sqlx::Error> {
    let now = unix_now_i64();
    sqlx::query(
        "UPDATE auth_attempts
         SET github_user_id = ?,
             github_login = ?,
             github_name = ?,
             github_verified_at_unix = ?
         WHERE id = ? AND expires_at_unix > ? AND consumed_at_unix IS NULL",
    )
    .bind(user.id)
    .bind(&user.login)
    .bind(&user.name)
    .bind(now)
    .bind(id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn record_github_device_flow(
    pool: &SqlitePool,
    id: &str,
    device_code: &str,
    interval_seconds: i64,
    expires_at_unix: i64,
    next_poll_at_unix: i64,
) -> Result<(), sqlx::Error> {
    let now = unix_now_i64();
    sqlx::query(
        "UPDATE auth_attempts
         SET github_device_code = ?,
             github_device_interval_seconds = ?,
             github_device_expires_at_unix = ?,
             github_device_next_poll_at_unix = ?
         WHERE id = ? AND expires_at_unix > ? AND consumed_at_unix IS NULL",
    )
    .bind(device_code)
    .bind(interval_seconds)
    .bind(expires_at_unix)
    .bind(next_poll_at_unix)
    .bind(id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

struct GitHubDeviceFlow {
    device_code: String,
    interval_seconds: i64,
    next_poll_at_unix: i64,
}

async fn github_device_flow(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<GitHubDeviceFlow>, sqlx::Error> {
    let now = unix_now_i64();
    let row = sqlx::query(
        "SELECT github_device_code,
                github_device_interval_seconds,
                github_device_next_poll_at_unix
         FROM auth_attempts
         WHERE id = ?
           AND expires_at_unix > ?
           AND consumed_at_unix IS NULL
           AND github_device_code IS NOT NULL
           AND github_device_expires_at_unix > ?",
    )
    .bind(id)
    .bind(now)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| GitHubDeviceFlow {
        device_code: row.get("github_device_code"),
        interval_seconds: row.get("github_device_interval_seconds"),
        next_poll_at_unix: row.get("github_device_next_poll_at_unix"),
    }))
}

async fn update_github_device_poll(
    pool: &SqlitePool,
    id: &str,
    interval_seconds: i64,
    next_poll_at_unix: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE auth_attempts
         SET github_device_interval_seconds = ?,
             github_device_next_poll_at_unix = ?
         WHERE id = ?",
    )
    .bind(interval_seconds)
    .bind(next_poll_at_unix)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn clear_github_device_flow(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE auth_attempts
         SET github_device_code = NULL,
             github_device_interval_seconds = NULL,
             github_device_expires_at_unix = NULL,
             github_device_next_poll_at_unix = NULL
         WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

struct LinkedProfile {
    profile_id: String,
    steam_id64: String,
    github_login: String,
}

enum AuthFinishError {
    InvalidAttempt,
    MissingSteam,
    MissingGitHub,
    ConflictingProfiles,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for AuthFinishError {
    fn from(value: sqlx::Error) -> Self {
        AuthFinishError::Database(value)
    }
}

async fn link_verified_auth_attempt(
    pool: &SqlitePool,
    id: &str,
) -> Result<LinkedProfile, AuthFinishError> {
    let now = unix_now_i64();
    let Some(row) = sqlx::query(
        "SELECT steam_id64, github_user_id, github_login, github_name
         FROM auth_attempts
         WHERE id = ?
           AND expires_at_unix > ?
           AND consumed_at_unix IS NULL",
    )
    .bind(id)
    .bind(now)
    .fetch_optional(pool)
    .await?
    else {
        return Err(AuthFinishError::InvalidAttempt);
    };

    let steam_id64 = row
        .get::<Option<String>, _>("steam_id64")
        .ok_or(AuthFinishError::MissingSteam)?;
    let github_user_id = row
        .get::<Option<i64>, _>("github_user_id")
        .ok_or(AuthFinishError::MissingGitHub)?;
    let github_login = row
        .get::<Option<String>, _>("github_login")
        .ok_or(AuthFinishError::MissingGitHub)?;
    let github_name = row.get::<Option<String>, _>("github_name");

    let steam_profile = sqlx::query_scalar::<_, String>(
        "SELECT profile_id FROM steam_accounts WHERE steam_id64 = ?",
    )
    .bind(&steam_id64)
    .fetch_optional(pool)
    .await?;
    let github_profile = sqlx::query_scalar::<_, String>(
        "SELECT profile_id FROM github_accounts WHERE github_user_id = ?",
    )
    .bind(github_user_id)
    .fetch_optional(pool)
    .await?;

    if let (Some(steam_profile), Some(github_profile)) = (&steam_profile, &github_profile) {
        if steam_profile != github_profile {
            return Err(AuthFinishError::ConflictingProfiles);
        }
    }

    let profile_id = steam_profile
        .or(github_profile)
        .unwrap_or_else(new_profile_id);
    let display_name = github_name.as_deref().unwrap_or(&github_login);

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO profiles (id, display_name, created_at_unix)
         VALUES (?, ?, ?)
         ON CONFLICT(id) DO UPDATE
         SET display_name = COALESCE(profiles.display_name, excluded.display_name)",
    )
    .bind(&profile_id)
    .bind(display_name)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO steam_accounts (steam_id64, profile_id, linked_at_unix, verified_at_unix)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(steam_id64) DO UPDATE
         SET verified_at_unix = excluded.verified_at_unix",
    )
    .bind(&steam_id64)
    .bind(&profile_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO github_accounts (github_user_id, github_login, profile_id, linked_at_unix, verified_at_unix)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(github_user_id) DO UPDATE
         SET github_login = excluded.github_login,
             verified_at_unix = excluded.verified_at_unix",
    )
    .bind(github_user_id)
    .bind(&github_login)
    .bind(&profile_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_events (event_type, subject_profile_id, created_at_unix, detail)
         VALUES ('dual_identity_verified', ?, ?, ?)",
    )
    .bind(&profile_id)
    .bind(now)
    .bind(format!(
        "steam_id64={steam_id64} github_user_id={github_user_id} github_login={github_login}"
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(LinkedProfile {
        profile_id,
        steam_id64,
        github_login,
    })
}

async fn consume_auth_attempt(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE auth_attempts SET consumed_at_unix = ? WHERE id = ?")
        .bind(unix_now_i64())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn profile_has_dual_identity(
    pool: &SqlitePool,
    profile_id: &str,
) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS (
            SELECT 1 FROM profiles p
            WHERE p.id = ?
              AND p.disabled_at_unix IS NULL
              AND EXISTS (SELECT 1 FROM steam_accounts s WHERE s.profile_id = p.id)
              AND EXISTS (SELECT 1 FROM github_accounts g WHERE g.profile_id = p.id)
        )",
    )
    .bind(profile_id)
    .fetch_one(pool)
    .await?;
    Ok(exists == 1)
}

async fn profile_has_root_role(pool: &SqlitePool, profile_id: &str) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS (
            SELECT 1 FROM profile_roles
            WHERE profile_id = ?
              AND role = 'root'
              AND revoked_at_unix IS NULL
        )",
    )
    .bind(profile_id)
    .fetch_one(pool)
    .await?;
    Ok(exists == 1)
}

async fn active_root_profile_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT profile_id)
         FROM profile_roles
         WHERE role = 'root' AND revoked_at_unix IS NULL",
    )
    .fetch_one(pool)
    .await
}

async fn grant_root(
    pool: &SqlitePool,
    profile_id: &str,
    actor_profile_id: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let now = unix_now_i64();
    let already_active = profile_has_root_role(pool, profile_id).await?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO profile_roles (profile_id, role, granted_at_unix, revoked_at_unix)
         VALUES (?, 'root', ?, NULL)
         ON CONFLICT(profile_id, role) DO UPDATE
         SET granted_at_unix = excluded.granted_at_unix,
             revoked_at_unix = NULL",
    )
    .bind(profile_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail)
         VALUES ('root_role_granted', ?, ?, ?, '')",
    )
    .bind(actor_profile_id)
    .bind(profile_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(!already_active)
}

async fn create_identity_session(
    pool: &SqlitePool,
    profile_id: &str,
) -> Result<(String, String, i64), sqlx::Error> {
    let now = unix_now_i64();
    let session_id = new_session_id();
    let token = new_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at_unix = now + DASHBOARD_SESSION_TTL_SECONDS;
    sqlx::query(
        "INSERT INTO identity_sessions
            (token_hash, session_id, profile_id, created_at_unix, expires_at_unix)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&token_hash)
    .bind(&session_id)
    .bind(profile_id)
    .bind(now)
    .bind(expires_at_unix)
    .execute(pool)
    .await?;
    Ok((session_id, token, expires_at_unix))
}

async fn root_session_profile_id(
    pool: &SqlitePool,
    headers: &HeaderMap,
) -> Result<Option<String>, sqlx::Error> {
    let Some(token) = session_token_from_headers(headers) else {
        return Ok(None);
    };
    let token_hash = hash_session_token(&token);
    let now = unix_now_i64();
    sqlx::query_scalar::<_, String>(
        "SELECT s.profile_id
         FROM identity_sessions s
         JOIN profiles p ON p.id = s.profile_id
         JOIN profile_roles r ON r.profile_id = s.profile_id
         WHERE s.token_hash = ?
           AND s.expires_at_unix > ?
           AND s.revoked_at_unix IS NULL
           AND p.disabled_at_unix IS NULL
           AND r.role = 'root'
           AND r.revoked_at_unix IS NULL
           AND EXISTS (SELECT 1 FROM steam_accounts steam WHERE steam.profile_id = s.profile_id)
           AND EXISTS (SELECT 1 FROM github_accounts github WHERE github.profile_id = s.profile_id)",
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
}

async fn admin_or_root_authorized(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<bool, sqlx::Error> {
    if authorized(headers, &state.admin_token) {
        return Ok(true);
    }
    Ok(root_session_profile_id(&state.pool, headers)
        .await?
        .is_some())
}

async fn active_roles(pool: &SqlitePool, profile_id: &str) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT role FROM profile_roles
         WHERE profile_id = ? AND revoked_at_unix IS NULL
         ORDER BY role",
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn link_steam_account(pool: &SqlitePool, steam_id64: &str) -> Result<String, sqlx::Error> {
    let now = unix_now_i64();
    if let Some(profile_id) = sqlx::query_scalar::<_, String>(
        "SELECT profile_id FROM steam_accounts WHERE steam_id64 = ?",
    )
    .bind(steam_id64)
    .fetch_optional(pool)
    .await?
    {
        sqlx::query("UPDATE steam_accounts SET verified_at_unix = ? WHERE steam_id64 = ?")
            .bind(now)
            .bind(steam_id64)
            .execute(pool)
            .await?;
        return Ok(profile_id);
    }

    let profile_id = new_profile_id();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO profiles (id, display_name, created_at_unix) VALUES (?, ?, ?)")
        .bind(&profile_id)
        .bind(format!("Steam {steam_id64}"))
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO steam_accounts (steam_id64, profile_id, linked_at_unix, verified_at_unix)
         VALUES (?, ?, ?, ?)",
    )
    .bind(steam_id64)
    .bind(&profile_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_events (event_type, subject_profile_id, created_at_unix, detail)
         VALUES ('steam_identity_linked', ?, ?, ?)",
    )
    .bind(&profile_id)
    .bind(now)
    .bind(format!("steam_id64={steam_id64}"))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(profile_id)
}

async fn link_github_account(
    pool: &SqlitePool,
    user: &GitHubUser,
    display_name: &str,
) -> Result<String, sqlx::Error> {
    let now = unix_now_i64();
    if let Some(profile_id) = sqlx::query_scalar::<_, String>(
        "SELECT profile_id FROM github_accounts WHERE github_user_id = ?",
    )
    .bind(user.id)
    .fetch_optional(pool)
    .await?
    {
        sqlx::query(
            "UPDATE github_accounts
             SET github_login = ?, verified_at_unix = ?
             WHERE github_user_id = ?",
        )
        .bind(&user.login)
        .bind(now)
        .bind(user.id)
        .execute(pool)
        .await?;
        sqlx::query("UPDATE profiles SET display_name = ? WHERE id = ? AND display_name IS NULL")
            .bind(display_name)
            .bind(&profile_id)
            .execute(pool)
            .await?;
        return Ok(profile_id);
    }

    let profile_id = new_profile_id();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO profiles (id, display_name, created_at_unix) VALUES (?, ?, ?)")
        .bind(&profile_id)
        .bind(display_name)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO github_accounts (github_user_id, github_login, profile_id, linked_at_unix, verified_at_unix)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user.id)
    .bind(&user.login)
    .bind(&profile_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_events (event_type, subject_profile_id, created_at_unix, detail)
         VALUES ('github_identity_linked', ?, ?, ?)",
    )
    .bind(&profile_id)
    .bind(now)
    .bind(format!(
        "github_user_id={} github_login={}",
        user.id, user.login
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(profile_id)
}

struct ProfileRow {
    profile_id: String,
    display_name: Option<String>,
    steam_ids: Option<String>,
    github_logins: Option<String>,
    roles: Option<String>,
}

async fn profile_rows(pool: &SqlitePool) -> Result<Vec<ProfileRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT
            p.id AS profile_id,
            p.display_name AS display_name,
            group_concat(DISTINCT s.steam_id64) AS steam_ids,
            group_concat(DISTINCT g.github_login) AS github_logins,
            group_concat(DISTINCT r.role) AS roles
         FROM profiles p
         LEFT JOIN steam_accounts s ON s.profile_id = p.id
         LEFT JOIN github_accounts g ON g.profile_id = p.id
         LEFT JOIN profile_roles r ON r.profile_id = p.id AND r.revoked_at_unix IS NULL
         WHERE p.disabled_at_unix IS NULL
         GROUP BY p.id, p.display_name
         ORDER BY p.created_at_unix DESC, p.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ProfileRow {
            profile_id: row.get("profile_id"),
            display_name: row.get("display_name"),
            steam_ids: row.get("steam_ids"),
            github_logins: row.get("github_logins"),
            roles: row.get("roles"),
        })
        .collect())
}

async fn profile_listing(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    let mut body = String::new();
    body.push_str("[[profiles]]\n");
    let rows = profile_rows(pool).await?;
    if rows.is_empty() {
        body.push_str("# no profiles\n");
        return Ok(body);
    }
    body.clear();
    for row in rows {
        body.push_str("[[profiles]]\n");
        body.push_str(&format!("id = {}\n", toml_string(&row.profile_id)));
        body.push_str(&format!(
            "display_name = {}\n",
            toml_string(row.display_name.as_deref().unwrap_or(""))
        ));
        body.push_str(&format!(
            "steam_ids = {}\n",
            toml_string(row.steam_ids.as_deref().unwrap_or(""))
        ));
        body.push_str(&format!(
            "github_logins = {}\n",
            toml_string(row.github_logins.as_deref().unwrap_or(""))
        ));
        body.push_str(&format!(
            "roles = {}\n\n",
            toml_string(row.roles.as_deref().unwrap_or(""))
        ));
    }
    Ok(body)
}

async fn verify_steam_ticket(
    http: &reqwest::Client,
    key: &str,
    app_id: u32,
    identity: &str,
    ticket_hex: &str,
) -> Result<String, Response> {
    let app_id = app_id.to_string();
    let response = http
        .get("https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/")
        .query(&[
            ("key", key),
            ("appid", app_id.as_str()),
            ("ticket", ticket_hex),
            ("identity", identity),
        ])
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: Steam verification request failed: {error}"),
            )
        })?;

    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: Steam rejected ticket with {}", response.status()),
        ));
    }

    let body = response.json::<Value>().await.map_err(|error| {
        text_response(
            StatusCode::BAD_GATEWAY,
            &format!("identity: failed to decode Steam response: {error}"),
        )
    })?;
    steam_id_from_response(&body).ok_or_else(|| {
        text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam response did not contain a verified steamid",
        )
    })
}

async fn verify_github_access_token(
    http: &reqwest::Client,
    access_token: &str,
) -> Result<GitHubUser, Response> {
    let response = http
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header(ACCEPT, "application/vnd.github+json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub verification request failed: {error}"),
            )
        })?;

    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub rejected token with {}", response.status()),
        ));
    }

    response.json::<GitHubUser>().await.map_err(|error| {
        text_response(
            StatusCode::BAD_GATEWAY,
            &format!("identity: failed to decode GitHub response: {error}"),
        )
    })
}

fn authorized(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {expected}"))
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(token.to_string());
    }

    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    cookie_header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            if name == SESSION_COOKIE && !value.is_empty() {
                Some(value.to_string())
            } else {
                None
            }
        })
}

fn session_cookie(config: &AuthConfig, token: &str, max_age_seconds: i64) -> String {
    let secure = if config.cookie_secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; Path={}; Max-Age={max_age_seconds}; HttpOnly; SameSite=Lax{secure}",
        config.cookie_path
    )
}

fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn dashboard_identity_ready(config: &AuthConfig) -> bool {
    config.steam_web_api_key.is_some() && config.github_client_id.is_some()
}

fn github_device_ready(config: &AuthConfig) -> bool {
    config.github_client_id.is_some()
}

fn unauthenticated_dashboard_html(config: &AuthConfig) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Identity Admin</title>\
         <style>body{{max-width:840px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}\
         pre{{background:#f7f7f7;padding:1rem;overflow:auto}}</style>\
         <h1>Vapor Identity Admin</h1>\
         <p>No valid root identity session is present.</p>\
         <h2>Required auth state</h2>\
         <ul><li>Steam verification configured: <code>{}</code></li>\
         <li>GitHub Device Flow configured: <code>{}</code></li>\
         <li>Session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <h2>Flow</h2>\
         <ol><li>Create an auth attempt with <code>POST /v1/auth/session/start</code>.</li>\
         <li>Attach Steam proof with <code>POST /v1/auth/session/steam/ticket</code>.</li>\
         <li>Attach GitHub proof with either <code>/github/device/start</code> + <code>/github/device/poll</code>, or <code>/github/token</code>.</li>\
         <li>Finish with <code>POST /v1/auth/session/finish</code>. The resulting profile must have an active <code>root</code> role.</li></ol>\
         <p>This page intentionally does not show profile data until the identity session exists and is still valid.</p>",
        config.steam_web_api_key.is_some(),
        config.github_client_id.is_some()
    )
}

fn unconfigured_dashboard_html(config: &AuthConfig) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Identity Admin</title>\
         <style>body{{max-width:840px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}</style>\
         <h1>Vapor Identity Admin</h1>\
         <p>The dashboard requires Steam and GitHub verification configuration before identity sessions can be trusted.</p>\
         <ul><li>Steam verification configured: <code>{}</code></li>\
         <li>GitHub client configured: <code>{}</code></li></ul>",
        config.steam_web_api_key.is_some(),
        config.github_client_id.is_some()
    )
}

fn valid_profile_id(value: &str) -> bool {
    value.starts_with("profile-")
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_auth_attempt_id(value: &str) -> bool {
    value.starts_with("auth-")
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_hex_ticket(ticket: &str) -> bool {
    !ticket.is_empty()
        && ticket.len() <= 8192
        && ticket.len().is_multiple_of(2)
        && ticket.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn steam_id_from_response(value: &Value) -> Option<String> {
    let params = value
        .pointer("/response/params")
        .or_else(|| value.get("response"))?;
    if let Some(result) = params.get("result").and_then(Value::as_str) {
        if result != "OK" {
            return None;
        }
    }
    params
        .get("steamid")
        .or_else(|| params.get("steam_id"))
        .and_then(Value::as_str)
        .filter(|steam_id| steam_id.bytes().all(|byte| byte.is_ascii_digit()))
        .map(ToOwned::to_owned)
}

fn new_profile_id() -> String {
    format!("profile-{}", Uuid::new_v4())
}

fn new_auth_attempt_id() -> String {
    format!("auth-{}", Uuid::new_v4())
}

fn new_session_id() -> String {
    format!("session-{}", Uuid::new_v4())
}

fn new_session_token() -> String {
    format!("vapor-session-{}-{}", Uuid::new_v4(), Uuid::new_v4())
}

fn text_response(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

fn unix_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("\"{escaped}\"")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
