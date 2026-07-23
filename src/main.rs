use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
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
        .route("/v1/auth/steam/ticket", post(auth_steam_ticket))
        .route("/v1/auth/github/token", post(auth_github_token))
        .route("/v1/admin/profiles", get(list_profiles))
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
        "service = \"vapor-identity-server\"\ndatabase = \"sqlite\"\nschema_version = {schema_version}\ninitialized = {initialized}\nsteam_identity_ready = {}\ngithub_identity_ready = {}\ndashboard_ready = {}\n",
        state.config.steam_web_api_key.is_some(),
        state.config.github_client_id.is_some(),
        state.config.dashboard_password.is_some()
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
        dashboard_ready: state.config.dashboard_password.is_some(),
    })
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
    if !authorized(&headers, &state.admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin token\n".to_string(),
        );
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
    if !authorized(&headers, &state.admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin token\n".to_string(),
        );
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

async fn admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !dashboard_authorized(&headers, &state.config.dashboard_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"Vapor Identity\"")],
            "missing or invalid dashboard credentials\n".to_string(),
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
         <p>Closed pre-alpha HTTP access is temporarily allowed before DNS is ready. Switch this dashboard to HTTPS once DNS is active.</p>\
         <h2>Readiness</h2>\
         <ul><li>Steam verification configured: <code>{}</code></li>\
         <li>GitHub client configured: <code>{}</code></li></ul>\
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
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (1, 'initial_identity_schema', ?)",
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
    Ok(body)
}

async fn count_rows(pool: &SqlitePool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = match table {
        "profiles" => "SELECT COUNT(*) FROM profiles",
        "steam_accounts" => "SELECT COUNT(*) FROM steam_accounts",
        "github_accounts" => "SELECT COUNT(*) FROM github_accounts",
        "profile_roles" => "SELECT COUNT(*) FROM profile_roles",
        "audit_events" => "SELECT COUNT(*) FROM audit_events",
        _ => unreachable!("table name is constrained by caller"),
    };
    sqlx::query_scalar(sql).fetch_one(pool).await
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

fn authorized(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {expected}"))
}

fn dashboard_authorized(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    decoded == format!("root:{expected}")
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
