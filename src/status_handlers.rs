use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::config::DASHBOARD_SESSION_TTL_SECONDS;
use crate::persistence::*;
use crate::types::*;
use crate::util::{authorized, dashboard_identity_ready, github_browser_ready};
pub(crate) async fn healthz() -> &'static str {
    "ok\n"
}

pub(crate) async fn status(State(state): State<AppState>) -> impl IntoResponse {
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

pub(crate) async fn auth_status(State(state): State<AppState>) -> Json<AuthStatus> {
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

pub(crate) async fn init(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
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

pub(crate) async fn export_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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
