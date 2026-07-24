mod admin_handlers;
mod api_handlers;
mod auth_attempts;
mod browser_handlers;
mod config;
mod db;
mod persistence;
mod profiles;
mod provider_handlers;
mod providers;
mod session_handlers;
mod status_handlers;
mod types;
mod util;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::net::TcpListener;

use crate::api_handlers::*;
use crate::browser_handlers::*;
use crate::config::{
    read_auth_config, DEFAULT_BIND, DEFAULT_DB_NAME, DEFAULT_STATE_DIR, MAX_AUTH_BODY_BYTES,
};
use crate::db::{open_database, run_migrations};
use crate::types::AppState;

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
        .route("/v1/admin/roles/grant", post(grant_profile_role))
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
