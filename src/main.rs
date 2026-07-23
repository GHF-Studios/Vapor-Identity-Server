use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::net::TcpListener;

const DEFAULT_BIND: &str = "127.0.0.1:7113";
const DEFAULT_STATE_DIR: &str = "state/identity";

#[derive(Clone)]
struct AppState {
    state_dir: Arc<PathBuf>,
    admin_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("VAPOR_IDENTITY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let state_dir = PathBuf::from(
        env::var("VAPOR_IDENTITY_STATE").unwrap_or_else(|_| DEFAULT_STATE_DIR.into()),
    );
    fs::create_dir_all(&state_dir).await?;

    let state = AppState {
        state_dir: Arc::new(state_dir),
        admin_token: env::var("VAPOR_IDENTITY_ADMIN_TOKEN")
            .ok()
            .filter(|value| !value.is_empty()),
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/v1/init", post(init))
        .route("/v1/export", get(export_identity))
        .with_state(state);

    let listener = TcpListener::bind(&bind).await?;
    eprintln!("vapor-identity-server listening on {bind}");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let registry = state.state_dir.join("registry.toml");
    let initialized = registry.exists();
    let body = format!(
        "service = \"vapor-identity-server\"\ninitialized = {initialized}\nsteam_identity = \"planned\"\ngithub_identity = \"planned\"\n"
    );
    (StatusCode::OK, body)
}

async fn init(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&headers, &state.admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin token\n".to_string(),
        );
    }

    let registry = state.state_dir.join("registry.toml");
    if registry.exists() {
        return (
            StatusCode::CONFLICT,
            "identity registry already initialized\n".to_string(),
        );
    }

    if let Err(error) = fs::create_dir_all(&*state.state_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("identity: failed to create state directory: {error}\n"),
        );
    }

    let contents = format!(
        "schema_version = 1\ninitialized_at_unix = {}\n\n[policy]\nplayers_require_github = false\ndevelopers_require_steam = true\ndevelopers_require_github = true\nroot_requires_role = true\n",
        unix_now()
    );
    if let Err(error) = fs::write(registry, contents).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("identity: failed to write registry: {error}\n"),
        );
    }

    (StatusCode::CREATED, "identity: initialized\n".to_string())
}

async fn export_identity(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&headers, &state.admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin token\n".to_string(),
        );
    }

    let registry = state.state_dir.join("registry.toml");
    let body = fs::read_to_string(registry).await.unwrap_or_else(|_| {
        "schema_version = 1\ninitialized = false\n# no identity registry has been initialized\n"
            .to_string()
    });
    (StatusCode::OK, body)
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
