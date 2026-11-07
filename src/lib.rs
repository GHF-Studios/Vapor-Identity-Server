mod admin_handlers;
mod api_handlers;
mod auth_attempts;
mod authorization_handlers;
mod automation_credentials;
mod browser_handlers;
mod cli_authorizations;
mod config;
mod db;
mod entitlements;
mod permission_requests;
mod persistence;
mod profiles;
mod provider_handlers;
mod providers;
mod session_handlers;
mod status_handlers;
mod types;
mod util;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::header::CACHE_CONTROL;
use axum::http::Request;
use axum::middleware::{from_fn, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;

use crate::api_handlers::*;
use crate::authorization_handlers::check_authorization;
use crate::automation_credentials::{
    create_automation_credential, list_automation_credentials, revoke_automation_credential,
    verify_automation_credential,
};
use crate::browser_handlers::*;
use crate::cli_authorizations::{
    approve_ssh_authorization, poll_ssh_authorization, ssh_authorization_page,
    start_ssh_authorization,
};
use crate::config::{read_auth_config, DEFAULT_DB_NAME, DEFAULT_STATE_DIR, MAX_AUTH_BODY_BYTES};
use crate::db::{open_database, run_migrations};
use crate::permission_requests::{
    approve_permission_request, create_permission_request, list_permission_requests,
    reject_permission_request, sweep_expired_permission_requests,
};
use crate::types::AppState;

pub struct HostRouters {
    pub api: Router,
    pub web: Router,
}

pub async fn app_router_from_env() -> Result<Router, Box<dyn std::error::Error>> {
    let routers = routers_from_env().await?;
    Ok(Router::new().merge(routers.api).merge(routers.web))
}

pub async fn routers_from_env() -> Result<HostRouters, Box<dyn std::error::Error>> {
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
    let http = crate::providers::provider_http_client()?;

    let state = AppState {
        pool,
        db_path: Arc::new(db_path),
        admin_token: env::var("VAPOR_IDENTITY_ADMIN_TOKEN")
            .ok()
            .filter(|value| !value.is_empty()),
        platform_request_authz_token: env::var("VAPOR_IDENTITY_PLATFORM_REQUEST_AUTHZ_TOKEN")
            .ok()
            .filter(|value| !value.is_empty()),
        config,
        http,
    };
    let expiry_pool = state.pool.clone();
    tokio::spawn(async move {
        loop {
            if sweep_expired_permission_requests(&expiry_pool)
                .await
                .is_err()
            {
                eprintln!("Identity permission-request expiry sweep failed; it will retry.");
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    let api = Router::new()
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
        .route(
            "/v1/cli/ssh-authorization/start",
            post(start_ssh_authorization),
        )
        .route(
            "/v1/cli/ssh-authorization/poll",
            post(poll_ssh_authorization),
        )
        .route("/v1/auth/steam/ticket", post(auth_steam_ticket))
        .route("/v1/auth/github/token", post(auth_github_token))
        .route(
            "/v1/internal/authorization/check",
            post(check_authorization),
        )
        .route(
            "/v1/internal/automation/verify",
            post(verify_automation_credential),
        )
        .route("/v1/admin/profiles", get(list_profiles))
        .route("/v1/admin/audit", get(list_audit_events))
        .route(
            "/v1/admin/automation-credentials",
            get(list_automation_credentials).post(create_automation_credential),
        )
        .route(
            "/v1/admin/automation-credentials/{id}/revoke",
            post(revoke_automation_credential),
        )
        .route(
            "/v1/admin/permission-requests",
            get(list_permission_requests).post(create_permission_request),
        )
        .route(
            "/v1/admin/permission-requests/{id}/approve",
            post(approve_permission_request),
        )
        .route(
            "/v1/admin/permission-requests/{id}/reject",
            post(reject_permission_request),
        )
        .route("/v1/admin/roles/grant", post(grant_profile_role))
        .route("/v1/admin/roles/revoke", post(revoke_profile_role))
        .route("/v1/init", post(init))
        .route("/v1/export", get(export_identity))
        .route_layer(from_fn(no_store_admin_responses))
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
        .with_state(state.clone());
    let web = Router::new()
        .route("/login", get(login_page))
        .route("/login/", get(login_page))
        .route("/login/steam", get(login_steam_start))
        .route("/login/steam/callback", get(login_steam_callback))
        .route("/login/github", get(login_github_start))
        .route("/login/github/callback", get(login_github_callback))
        .route(
            "/cli/ssh/authorize",
            get(ssh_authorization_page)
                .post(approve_ssh_authorization)
                .layer(from_fn(no_store_admin_responses)),
        )
        .route("/logout", get(logout))
        .route("/admin/identity", get(admin_dashboard))
        .route("/admin/identity/", get(admin_dashboard))
        .route("/admin/identity/roles/grant", post(admin_grant_role_form))
        .route("/admin/identity/roles/revoke", post(admin_revoke_role_form))
        .route(
            "/admin/identity/automation-credentials",
            post(admin_create_automation_credential_form),
        )
        .route(
            "/admin/identity/automation-credentials/{id}/revoke",
            post(admin_revoke_automation_credential_form),
        )
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
        .with_state(state);

    Ok(HostRouters { api, web })
}

async fn no_store_admin_responses(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
