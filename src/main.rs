use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE};
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
use std::collections::HashMap;
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
const BROWSER_LOGIN_ATTEMPT_TTL_SECONDS: i64 = 10 * 60;
const DASHBOARD_SESSION_TTL_SECONDS: i64 = 5 * 60;
const SESSION_COOKIE: &str = "vapor_identity_session";
const STEAM_OPENID_ENDPOINT: &str = "https://steamcommunity.com/openid/login";

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
    github_client_secret: Option<String>,
    dashboard_password: Option<String>,
    cookie_secure: bool,
    cookie_path: String,
    public_origin: Option<String>,
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
struct GitHubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
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
    github_browser_login_ready: bool,
    github_client_secret_configured: bool,
    steam_browser_login_ready: bool,
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
        .route("/login", get(login_page))
        .route("/login/", get(login_page))
        .route("/login/steam", get(login_steam_start))
        .route("/login/steam/callback", get(login_steam_callback))
        .route("/login/github", get(login_github_start))
        .route("/login/github/callback", get(login_github_callback))
        .route("/logout", get(logout))
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
        github_client_secret: env::var("VAPOR_IDENTITY_GITHUB_CLIENT_SECRET")
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
            .unwrap_or_else(|| "/".to_string()),
        public_origin: env::var("VAPOR_IDENTITY_PUBLIC_ORIGIN")
            .ok()
            .filter(|value| valid_public_origin(value)),
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
        "service = \"vapor-identity-server\"\ndatabase = \"sqlite\"\nschema_version = {schema_version}\ninitialized = {initialized}\nsteam_identity_ready = {}\nsteam_browser_login_ready = true\ngithub_identity_ready = {}\ngithub_browser_login_ready = {}\ndashboard_ready = {}\ndashboard_session_ttl_seconds = {DASHBOARD_SESSION_TTL_SECONDS}\n",
        state.config.steam_web_api_key.is_some(),
        state.config.github_client_id.is_some(),
        github_browser_ready(&state.config),
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
        github_browser_login_ready: github_browser_ready(&state.config),
        github_client_secret_configured: state.config.github_client_secret.is_some(),
        steam_browser_login_ready: true,
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

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to load login state: {error}\n"),
            )
                .into_response();
        }
    };

    Html(login_html(&state.config, current.as_ref())).into_response()
}

async fn login_steam_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let state_token = new_browser_login_state();
    let now = unix_now_i64();
    if let Err(error) = create_browser_login_attempt(
        &state.pool,
        &state_token,
        "steam",
        None,
        now,
        now + BROWSER_LOGIN_ATTEMPT_TTL_SECONDS,
    )
    .await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to start Steam login: {error}"),
        );
    }

    let origin = public_origin(&state.config, &headers);
    let return_to = format!("{origin}/login/steam/callback?state={state_token}");
    let redirect = format!(
        "{STEAM_OPENID_ENDPOINT}?openid.ns={}&openid.mode=checkid_setup&openid.claimed_id={}&openid.identity={}&openid.return_to={}&openid.realm={}",
        percent_encode("http://specs.openid.net/auth/2.0"),
        percent_encode("http://specs.openid.net/auth/2.0/identifier_select"),
        percent_encode("http://specs.openid.net/auth/2.0/identifier_select"),
        percent_encode(&return_to),
        percent_encode(&format!("{origin}/")),
    );

    redirect_response(&redirect)
}

async fn login_steam_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(state_token) = params
        .get("state")
        .filter(|value| valid_browser_state(value))
    else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: missing or invalid state",
        );
    };
    match browser_login_attempt(&state.pool, state_token, "steam").await {
        Ok(Some(_attempt)) => {}
        Ok(None) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: Steam login attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read Steam login attempt: {error}"),
            );
        }
    }

    let origin = public_origin(&state.config, &headers);
    let expected_return_to = format!("{origin}/login/steam/callback?state={state_token}");
    if params
        .get("openid.return_to")
        .is_none_or(|return_to| return_to != &expected_return_to)
    {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID return_to did not match login attempt",
        );
    }

    let steam_id64 = match verify_steam_openid(&state.http, &params).await {
        Ok(steam_id64) => steam_id64,
        Err(response) => return response,
    };
    let profile_id = match link_steam_account(&state.pool, &steam_id64).await {
        Ok(profile_id) => profile_id,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to persist Steam profile: {error}"),
            );
        }
    };
    let (_session_id, token, _expires_at_unix) =
        match create_identity_session(&state.pool, &profile_id).await {
            Ok(session) => session,
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to create login session: {error}"),
                );
            }
        };
    if let Err(error) = consume_browser_login_attempt(&state.pool, state_token).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to consume Steam login attempt: {error}"),
        );
    }

    redirect_with_cookie(&state.config, "/login", &token)
}

async fn login_github_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !github_browser_ready(&state.config) {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub browser login is not configured",
        );
    }
    let Some(profile) = (match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to load login state: {error}"),
            );
        }
    }) else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: sign in with Steam before linking GitHub",
        );
    };

    let state_token = new_browser_login_state();
    let now = unix_now_i64();
    if let Err(error) = create_browser_login_attempt(
        &state.pool,
        &state_token,
        "github",
        Some(&profile.profile_id),
        now,
        now + BROWSER_LOGIN_ATTEMPT_TTL_SECONDS,
    )
    .await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to start GitHub login: {error}"),
        );
    }

    let origin = public_origin(&state.config, &headers);
    let redirect_uri = format!("{origin}/login/github/callback");
    let client_id = state.config.github_client_id.as_deref().unwrap_or_default();
    let redirect = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}&allow_signup=true",
        percent_encode(client_id),
        percent_encode(&redirect_uri),
        percent_encode("read:user"),
        percent_encode(&state_token),
    );
    redirect_response(&redirect)
}

async fn login_github_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GitHubCallbackQuery>,
) -> Response {
    if let Some(error) = query.error.as_deref() {
        let detail = query.error_description.as_deref().unwrap_or(error);
        return text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub authorization failed: {detail}"),
        );
    }
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return text_response(StatusCode::BAD_REQUEST, "identity: missing GitHub code");
    };
    let Some(state_token) = query
        .state
        .as_deref()
        .filter(|value| valid_browser_state(value))
    else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: missing or invalid state",
        );
    };
    let Some(client_id) = state.config.github_client_id.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    };
    let Some(client_secret) = state.config.github_client_secret.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client secret is not configured",
        );
    };

    let attempt = match browser_login_attempt(&state.pool, state_token, "github").await {
        Ok(Some(attempt)) => attempt,
        Ok(None) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: GitHub login attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read GitHub login attempt: {error}"),
            );
        }
    };
    let Some(profile_id) = attempt.profile_id else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub browser login must attach to a Steam profile",
        );
    };
    if current_profile_from_headers(&state.pool, &headers)
        .await
        .ok()
        .flatten()
        .is_none_or(|profile| profile.profile_id != profile_id)
    {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub login attempt does not match current Steam session",
        );
    }

    let origin = public_origin(&state.config, &headers);
    let redirect_uri = format!("{origin}/login/github/callback");
    let token =
        match exchange_github_web_code(&state.http, client_id, client_secret, code, &redirect_uri)
            .await
        {
            Ok(token) => token,
            Err(response) => return response,
        };
    let user = match verify_github_access_token(&state.http, &token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let display_name = user.name.as_deref().unwrap_or(&user.login);
    if let Err(error) =
        link_github_account_to_profile(&state.pool, &profile_id, &user, display_name).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to link GitHub identity: {error}"),
        );
    }
    if let Err(error) = consume_browser_login_attempt(&state.pool, state_token).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to consume GitHub login attempt: {error}"),
        );
    }

    redirect_response("/login")
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = session_token_from_headers(&headers) {
        if let Err(error) = revoke_identity_session(&state.pool, &token).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to revoke session: {error}\n"),
            )
                .into_response();
        }
    }
    (
        StatusCode::SEE_OTHER,
        [
            (SET_COOKIE, expired_session_cookie(&state.config)),
            (LOCATION, "/login".to_string()),
        ],
        "",
    )
        .into_response()
}

async fn admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to validate dashboard session: {error}\n"),
            )
                .into_response();
        }
    };
    let Some(current) = current else {
        return Html(admin_locked_html(None)).into_response();
    };
    if !current.root_authorized {
        return Html(admin_locked_html(Some(&current))).into_response();
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
         <p>Signed in as Steam profile <code>{}</code>. Root role is active.</p>\
         <p><a href=\"/login\">Identity</a> · <a href=\"/logout\">Logout</a></p>\
         <h2>Readiness</h2>\
         <ul><li>Steam browser login: <code>true</code></li>\
         <li>GitHub browser login configured: <code>{}</code></li>\
         <li>Dashboard session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <h2>Profiles</h2><table><thead><tr><th>Profile</th><th>Name</th><th>Steam</th><th>GitHub</th><th>Roles</th></tr></thead><tbody>{rows}</tbody></table>",
        html_escape(&current.profile_id),
        github_browser_ready(&state.config)
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
        "CREATE TABLE IF NOT EXISTS browser_login_attempts (
            state TEXT PRIMARY KEY,
            flow TEXT NOT NULL CHECK (flow IN ('steam', 'github')),
            profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            consumed_at_unix INTEGER
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
        "CREATE INDEX IF NOT EXISTS idx_browser_login_attempts_active
         ON browser_login_attempts (flow, expires_at_unix, consumed_at_unix)",
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
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (3, 'browser_login_attempts', ?)",
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
    let browser_login_attempt_count = count_rows(pool, "browser_login_attempts").await?;

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
    body.push_str(&format!(
        "browser_login_attempts = {browser_login_attempt_count}\n"
    ));
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
        "browser_login_attempts" => "SELECT COUNT(*) FROM browser_login_attempts",
        _ => unreachable!("table name is constrained by caller"),
    };
    sqlx::query_scalar(sql).fetch_one(pool).await
}

struct BrowserLoginAttempt {
    profile_id: Option<String>,
}

async fn create_browser_login_attempt(
    pool: &SqlitePool,
    state: &str,
    flow: &str,
    profile_id: Option<&str>,
    now: i64,
    expires_at_unix: i64,
) -> Result<(), sqlx::Error> {
    prune_expired_auth_state(pool, now).await?;
    sqlx::query(
        "INSERT INTO browser_login_attempts
            (state, flow, profile_id, created_at_unix, expires_at_unix)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(state)
    .bind(flow)
    .bind(profile_id)
    .bind(now)
    .bind(expires_at_unix)
    .execute(pool)
    .await?;
    Ok(())
}

async fn browser_login_attempt(
    pool: &SqlitePool,
    state: &str,
    flow: &str,
) -> Result<Option<BrowserLoginAttempt>, sqlx::Error> {
    let now = unix_now_i64();
    let row = sqlx::query(
        "SELECT profile_id
         FROM browser_login_attempts
         WHERE state = ?
           AND flow = ?
           AND expires_at_unix > ?
           AND consumed_at_unix IS NULL",
    )
    .bind(state)
    .bind(flow)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| BrowserLoginAttempt {
        profile_id: row.get("profile_id"),
    }))
}

async fn consume_browser_login_attempt(pool: &SqlitePool, state: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE browser_login_attempts SET consumed_at_unix = ? WHERE state = ?")
        .bind(unix_now_i64())
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
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
        "DELETE FROM browser_login_attempts
         WHERE expires_at_unix <= ? OR consumed_at_unix IS NOT NULL",
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

    let profile_id = match (steam_profile, github_profile) {
        (Some(profile_id), None) | (Some(profile_id), Some(_)) => profile_id,
        (None, Some(_)) => return Err(AuthFinishError::ConflictingProfiles),
        (None, None) => new_profile_id(),
    };
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

struct CurrentProfile {
    profile_id: String,
    display_name: Option<String>,
    steam_id64: Option<String>,
    github_login: Option<String>,
    roles: Vec<String>,
    root_authorized: bool,
}

async fn current_profile_from_headers(
    pool: &SqlitePool,
    headers: &HeaderMap,
) -> Result<Option<CurrentProfile>, sqlx::Error> {
    let Some(profile_id) = session_profile_id(pool, headers).await? else {
        return Ok(None);
    };
    profile_by_id(pool, &profile_id).await
}

async fn session_profile_id(
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
         WHERE s.token_hash = ?
           AND s.expires_at_unix > ?
           AND s.revoked_at_unix IS NULL
           AND p.disabled_at_unix IS NULL",
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
}

async fn profile_by_id(
    pool: &SqlitePool,
    profile_id: &str,
) -> Result<Option<CurrentProfile>, sqlx::Error> {
    let Some(row) = sqlx::query(
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
         WHERE p.id = ? AND p.disabled_at_unix IS NULL
         GROUP BY p.id, p.display_name",
    )
    .bind(profile_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let steam_id64 = first_csv(row.get::<Option<String>, _>("steam_ids").as_deref());
    let github_login = first_csv(row.get::<Option<String>, _>("github_logins").as_deref());
    let roles = row
        .get::<Option<String>, _>("roles")
        .as_deref()
        .map(csv_values)
        .unwrap_or_default();
    let root_authorized =
        roles.iter().any(|role| role == "root") && steam_id64.is_some() && github_login.is_some();

    Ok(Some(CurrentProfile {
        profile_id: row.get("profile_id"),
        display_name: row.get("display_name"),
        steam_id64,
        github_login,
        roles,
        root_authorized,
    }))
}

async fn revoke_identity_session(pool: &SqlitePool, token: &str) -> Result<(), sqlx::Error> {
    let token_hash = hash_session_token(token);
    sqlx::query(
        "UPDATE identity_sessions
         SET revoked_at_unix = COALESCE(revoked_at_unix, ?)
         WHERE token_hash = ?",
    )
    .bind(unix_now_i64())
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
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

async fn link_github_account_to_profile(
    pool: &SqlitePool,
    profile_id: &str,
    user: &GitHubUser,
    display_name: &str,
) -> Result<(), sqlx::Error> {
    let now = unix_now_i64();
    if let Some(existing_profile_id) = sqlx::query_scalar::<_, String>(
        "SELECT profile_id FROM github_accounts WHERE github_user_id = ?",
    )
    .bind(user.id)
    .fetch_optional(pool)
    .await?
    {
        if existing_profile_id != profile_id {
            return Err(sqlx::Error::RowNotFound);
        }
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
            .bind(profile_id)
            .execute(pool)
            .await?;
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE profiles SET display_name = COALESCE(display_name, ?) WHERE id = ?")
        .bind(display_name)
        .bind(profile_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO github_accounts (github_user_id, github_login, profile_id, linked_at_unix, verified_at_unix)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user.id)
    .bind(&user.login)
    .bind(profile_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_events (event_type, subject_profile_id, created_at_unix, detail)
         VALUES ('github_identity_linked', ?, ?, ?)",
    )
    .bind(profile_id)
    .bind(now)
    .bind(format!(
        "github_user_id={} github_login={}",
        user.id, user.login
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
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

async fn verify_steam_openid(
    http: &reqwest::Client,
    params: &HashMap<String, String>,
) -> Result<String, Response> {
    if params
        .get("openid.op_endpoint")
        .is_none_or(|value| value != STEAM_OPENID_ENDPOINT)
    {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID endpoint did not match Steam",
        ));
    }

    let claimed_id = params
        .get("openid.claimed_id")
        .ok_or_else(|| text_response(StatusCode::BAD_REQUEST, "identity: missing claimed_id"))?;
    let steam_id64 = steam_id_from_openid_claim(claimed_id).ok_or_else(|| {
        text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID claimed_id did not contain SteamID64",
        )
    })?;
    if params
        .get("openid.identity")
        .is_none_or(|identity| identity != claimed_id)
    {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID identity did not match claimed_id",
        ));
    }

    let mut form = Vec::new();
    for (key, value) in params {
        if key.starts_with("openid.") {
            if key == "openid.mode" {
                form.push((key.clone(), "check_authentication".to_string()));
            } else {
                form.push((key.clone(), value.clone()));
            }
        }
    }
    if !form.iter().any(|(key, _)| key == "openid.mode") {
        form.push((
            "openid.mode".to_string(),
            "check_authentication".to_string(),
        ));
    }

    let response = http
        .post(STEAM_OPENID_ENDPOINT)
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&form)
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: Steam OpenID verification failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "identity: Steam OpenID verification returned {}",
                response.status()
            ),
        ));
    }
    let body = response.text().await.map_err(|error| {
        text_response(
            StatusCode::BAD_GATEWAY,
            &format!("identity: failed to read Steam OpenID response: {error}"),
        )
    })?;
    if !body.lines().any(|line| line.trim() == "is_valid:true") {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID response was not valid",
        ));
    }

    Ok(steam_id64)
}

async fn exchange_github_web_code(
    http: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, Response> {
    let response = http
        .post("https://github.com/login/oauth/access_token")
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub code exchange failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub rejected code with {}", response.status()),
        ));
    }
    let token_response = response
        .json::<GitHubAccessTokenResponse>()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub code exchange response: {error}"),
            )
        })?;
    if let Some(error) = token_response.error.as_deref() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub code exchange returned {error}"),
        ));
    }
    token_response.access_token.ok_or_else(|| {
        text_response(
            StatusCode::BAD_GATEWAY,
            "identity: GitHub code exchange did not return an access token",
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

fn expired_session_cookie(config: &AuthConfig) -> String {
    let secure = if config.cookie_secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}=; Path={}; Max-Age=0; HttpOnly; SameSite=Lax{secure}",
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
    github_browser_ready(config)
}

fn github_browser_ready(config: &AuthConfig) -> bool {
    config.github_client_id.is_some() && config.github_client_secret.is_some()
}

fn github_device_ready(config: &AuthConfig) -> bool {
    config.github_client_id.is_some()
}

fn login_html(config: &AuthConfig, current: Option<&CurrentProfile>) -> String {
    let body = if let Some(profile) = current {
        let roles = display_roles(profile);
        let github = profile.github_login.as_deref().unwrap_or("not linked");
        let github_action = if profile.github_login.is_some() {
            "<p>GitHub identity is linked.</p>".to_string()
        } else if github_browser_ready(config) {
            "<p><a href=\"/login/github\">Link GitHub account</a></p>".to_string()
        } else {
            "<p>GitHub browser login is not configured yet. Steam/player login still works.</p>"
                .to_string()
        };
        format!(
            "<p>Signed in as Steam profile <code>{}</code>.</p>\
             <dl><dt>Display name</dt><dd>{}</dd>\
             <dt>SteamID64</dt><dd>{}</dd>\
             <dt>GitHub</dt><dd>{}</dd>\
             <dt>Roles</dt><dd>{}</dd></dl>\
             {github_action}\
             <p><a href=\"/admin\">Open admin dashboard</a> · <a href=\"/logout\">Logout</a></p>",
            html_escape(&profile.profile_id),
            html_escape(profile.display_name.as_deref().unwrap_or("")),
            html_escape(profile.steam_id64.as_deref().unwrap_or("")),
            html_escape(github),
            html_escape(&roles),
        )
    } else {
        "<p>Vapor profiles are anchored by Steam identity. No Vapor username or password is required.</p>\
         <p><a href=\"/login/steam\">Sign in / register with Steam</a></p>\
         <p>GitHub is linked after Steam login when development or root access is needed.</p>"
            .to_string()
    };

    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Login</title>\
         <style>body{{max-width:840px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}dt{{font-weight:700}}dd{{margin:0 0 .5rem 0}}</style>\
         <h1>Vapor Login</h1>{body}\
         <h2>Readiness</h2>\
         <ul><li>Steam browser login: <code>true</code></li>\
         <li>GitHub browser login configured: <code>{}</code></li>\
         <li>GitHub Device Flow configured: <code>{}</code></li>\
         <li>Session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <p><a href=\"/\">Home</a></p>",
        github_browser_ready(config),
        config.github_client_id.is_some()
    )
}

fn admin_locked_html(current: Option<&CurrentProfile>) -> String {
    let body = if let Some(profile) = current {
        format!(
            "<p>You are signed in as Steam profile <code>{}</code>, but this profile is not authorized for root/admin access.</p>\
             <dl><dt>SteamID64</dt><dd>{}</dd><dt>GitHub</dt><dd>{}</dd><dt>Roles</dt><dd>{}</dd></dl>\
             <p><a href=\"/login\">Manage identity</a> · <a href=\"/logout\">Logout</a></p>",
            html_escape(&profile.profile_id),
            html_escape(profile.steam_id64.as_deref().unwrap_or("")),
            html_escape(profile.github_login.as_deref().unwrap_or("not linked")),
            html_escape(&display_roles(profile)),
        )
    } else {
        "<p>The admin dashboard is publicly reachable, but locked. Sign in to check whether your Steam profile has admin access.</p>\
         <p><a href=\"/login\">Login / register</a></p>"
            .to_string()
    };

    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Identity Admin</title>\
         <style>body{{max-width:840px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}dt{{font-weight:700}}dd{{margin:0 0 .5rem 0}}</style>\
         <h1>Vapor Identity Admin</h1>{body}\
         <p>Admin access requires linked Steam and GitHub identities plus the <code>root</code> role.</p>"
    )
}

fn display_roles(profile: &CurrentProfile) -> String {
    let mut roles = vec!["player".to_string()];
    roles.extend(profile.roles.iter().cloned());
    roles.sort();
    roles.dedup();
    roles.join(", ")
}

fn redirect_response(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, location.to_string())],
        "",
    )
        .into_response()
}

fn redirect_with_cookie(config: &AuthConfig, location: &str, token: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (
                SET_COOKIE,
                session_cookie(config, token, DASHBOARD_SESSION_TTL_SECONDS),
            ),
            (LOCATION, location.to_string()),
        ],
        "",
    )
        .into_response()
}

fn public_origin(config: &AuthConfig, headers: &HeaderMap) -> String {
    if let Some(origin) = config.public_origin.as_deref() {
        return origin.to_string();
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_public_host(value))
        .unwrap_or("127.0.0.1:7113");
    format!("{proto}://{host}")
}

fn valid_public_origin(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.ends_with('/')
        && !value.contains(';')
        && !value.contains('\r')
        && !value.contains('\n')
}

fn valid_public_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains(';')
        && !value.contains('\r')
        && !value.contains('\n')
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn steam_id_from_openid_claim(value: &str) -> Option<String> {
    let steam_id = value
        .strip_prefix("https://steamcommunity.com/openid/id/")
        .or_else(|| value.strip_prefix("http://steamcommunity.com/openid/id/"))?;
    if steam_id.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(steam_id.to_string())
    } else {
        None
    }
}

fn first_csv(value: Option<&str>) -> Option<String> {
    value
        .and_then(|value| value.split(',').find(|part| !part.trim().is_empty()))
        .map(|value| value.trim().to_string())
}

fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                None
            } else {
                Some(part.to_string())
            }
        })
        .collect()
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

fn valid_browser_state(value: &str) -> bool {
    value.starts_with("login-")
        && value.len() <= 96
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

fn new_browser_login_state() -> String {
    format!("login-{}-{}", Uuid::new_v4(), Uuid::new_v4())
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
