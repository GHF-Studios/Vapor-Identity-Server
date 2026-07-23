use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::path::Path;

use crate::util::{toml_string, unix_now_i64};

pub(crate) async fn open_database(db_path: &Path) -> Result<SqlitePool, sqlx::Error> {
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

pub(crate) async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
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

pub(crate) async fn initialize_identity(pool: &SqlitePool) -> Result<(), sqlx::Error> {
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

pub(crate) async fn is_initialized(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT value FROM service_metadata WHERE key = 'initialized_at_unix'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(value.is_some())
}

pub(crate) async fn schema_version(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let version =
        sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(version) FROM schema_migrations")
            .fetch_one(pool)
            .await?;
    Ok(version.unwrap_or(0))
}

pub(crate) async fn export_identity_state(
    pool: &SqlitePool,
    db_path: &Path,
) -> Result<String, sqlx::Error> {
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

pub(crate) async fn count_rows(pool: &SqlitePool, table: &str) -> Result<i64, sqlx::Error> {
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
