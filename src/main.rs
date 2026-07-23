use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::net::TcpListener;

const DEFAULT_BIND: &str = "127.0.0.1:7113";
const DEFAULT_STATE_DIR: &str = "state/identity";
const DEFAULT_DB_NAME: &str = "identity.sqlite3";

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    db_path: Arc<PathBuf>,
    admin_token: Option<String>,
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

    let state = AppState {
        pool,
        db_path: Arc::new(db_path),
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
        "service = \"vapor-identity-server\"\ndatabase = \"sqlite\"\nschema_version = {schema_version}\ninitialized = {initialized}\nsteam_identity = \"planned\"\ngithub_identity = \"planned\"\n"
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

fn authorized(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {expected}"))
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
