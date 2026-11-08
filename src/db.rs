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
        "CREATE TABLE IF NOT EXISTS steam_product_entitlement_cache (
            steam_id64 TEXT NOT NULL,
            product_id TEXT NOT NULL,
            active INTEGER NOT NULL CHECK (active IN (0, 1)),
            permanent INTEGER NOT NULL CHECK (permanent IN (0, 1)),
            checked_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            PRIMARY KEY (steam_id64, product_id)
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
        "CREATE TABLE IF NOT EXISTS automation_credentials (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
            label TEXT NOT NULL,
            scopes TEXT NOT NULL,
            created_by_profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            revoked_at_unix INTEGER
        )",
    )
    .execute(&mut *tx)
    .await?;
    let credential_columns = sqlx::query("PRAGMA table_info(automation_credentials)")
        .fetch_all(&mut *tx)
        .await?;
    if !credential_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "single_use")
    {
        sqlx::query("ALTER TABLE automation_credentials ADD COLUMN single_use INTEGER NOT NULL DEFAULT 0 CHECK (single_use IN (0, 1))")
            .execute(&mut *tx)
            .await?;
    }
    if !credential_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "use_count")
    {
        sqlx::query("ALTER TABLE automation_credentials ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0)")
            .execute(&mut *tx)
            .await?;
    }
    if !credential_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "bound_ssh_fingerprint")
    {
        sqlx::query("ALTER TABLE automation_credentials ADD COLUMN bound_ssh_fingerprint TEXT")
            .execute(&mut *tx)
            .await?;
    }
    if !credential_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "bound_ssh_request_hash")
    {
        sqlx::query("ALTER TABLE automation_credentials ADD COLUMN bound_ssh_request_hash TEXT")
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cli_ssh_authorizations (
            id TEXT PRIMARY KEY,
            device_code_hash TEXT NOT NULL UNIQUE CHECK (length(device_code_hash) = 64),
            user_code_hash TEXT NOT NULL UNIQUE CHECK (length(user_code_hash) = 64),
            ssh_fingerprint TEXT NOT NULL,
            purpose TEXT NOT NULL,
            capabilities TEXT NOT NULL,
            requested_duration_seconds INTEGER NOT NULL CHECK (requested_duration_seconds BETWEEN 3600 AND 28800),
            status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
            approved_by_profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            last_poll_at_unix INTEGER,
            consumed_at_unix INTEGER
        )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cli_ssh_authorizations_expiry
         ON cli_ssh_authorizations (status, expires_at_unix)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS permission_requests (
            id TEXT PRIMARY KEY,
            body_hash TEXT NOT NULL CHECK (length(body_hash) = 64),
            action TEXT NOT NULL CHECK (action IN ('grant', 'revoke')),
            role TEXT NOT NULL CHECK (role IN ('root', 'content-developer')),
            steam_id64 TEXT NOT NULL,
            github_login TEXT NOT NULL,
            resolved_profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
            requester_profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
            requester_credential_id TEXT REFERENCES automation_credentials(id) ON DELETE RESTRICT,
            role_active_at_request INTEGER NOT NULL DEFAULT 0 CHECK (role_active_at_request IN (0, 1)),
            status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'rejected', 'cancelled', 'expired', 'stale')),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            decided_by_profile_id TEXT REFERENCES profiles(id) ON DELETE RESTRICT,
            decided_at_unix INTEGER,
            decision_reason TEXT
        )",
    )
    .execute(&mut *tx)
    .await?;
    let permission_request_columns = sqlx::query("PRAGMA table_info(permission_requests)")
        .fetch_all(&mut *tx)
        .await?;
    if !permission_request_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "role_active_at_request")
    {
        sqlx::query("ALTER TABLE permission_requests ADD COLUMN role_active_at_request INTEGER NOT NULL DEFAULT 0 CHECK (role_active_at_request IN (0, 1))")
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_permission_requests_status
         ON permission_requests (status, expires_at_unix, created_at_unix)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_permission_requests_created
         ON permission_requests (created_at_unix DESC, id DESC)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO service_metadata (key, value, updated_at_unix)
         VALUES ('permission_mutation_lock', '0', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_automation_credentials_active
         ON automation_credentials (expires_at_unix, revoked_at_unix)",
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
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (4, 'steam_product_entitlement_cache', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (5, 'scoped_automation_credentials', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (6, 'permission_change_requests', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (7, 'permission_role_state_snapshot', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_unix)
         VALUES (8, 'one_time_cli_ssh_authorization', ?)",
    )
    .bind(unix_now_i64())
    .execute(&mut *tx)
    .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS project_memberships (
        project_id TEXT NOT NULL CHECK(length(project_id) BETWEEN 3 AND 127 AND project_id NOT GLOB '*[^a-z0-9_/-]*' AND instr(project_id, '/') BETWEEN 2 AND 64 AND length(substr(project_id, instr(project_id, '/') + 1)) BETWEEN 1 AND 63 AND instr(substr(project_id, instr(project_id, '/') + 1), '/') = 0),
        profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
        role TEXT NOT NULL CHECK(role IN ('owner', 'developer', 'viewer')),
        version INTEGER NOT NULL CHECK(version > 0),
        granted_by_profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
        granted_at_unix INTEGER NOT NULL,
        revoked_by_profile_id TEXT REFERENCES profiles(id) ON DELETE RESTRICT,
        revoked_at_unix INTEGER,
        PRIMARY KEY(project_id, profile_id)
    )").execute(&mut *tx).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_project_memberships_profile ON project_memberships(profile_id, revoked_at_unix)").execute(&mut *tx).await?;
    sqlx::query("INSERT OR IGNORE INTO schema_migrations(version, name, applied_at_unix) VALUES (9, 'project_memberships', ?)").bind(unix_now_i64()).execute(&mut *tx).await?;
    let session_columns = sqlx::query("PRAGMA table_info(identity_sessions)")
        .fetch_all(&mut *tx)
        .await?;
    if !session_columns
        .iter()
        .any(|r| r.get::<String, _>("name") == "purpose")
    {
        sqlx::query("ALTER TABLE identity_sessions ADD COLUMN purpose TEXT NOT NULL DEFAULT 'operator' CHECK(purpose IN ('operator', 'user'))").execute(&mut *tx).await?;
    }
    let split_applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations WHERE version = 10")
            .fetch_one(&mut *tx)
            .await?;
    if split_applied == 0 {
        sqlx::query("ALTER TABLE browser_login_attempts RENAME TO browser_login_attempts_old")
            .execute(&mut *tx)
            .await?;
        sqlx::query("CREATE TABLE browser_login_attempts (state TEXT PRIMARY KEY, flow TEXT NOT NULL CHECK(flow IN ('steam','github','user-steam','user-github')), profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE, created_at_unix INTEGER NOT NULL, expires_at_unix INTEGER NOT NULL, consumed_at_unix INTEGER)").execute(&mut *tx).await?;
        sqlx::query("INSERT INTO browser_login_attempts SELECT * FROM browser_login_attempts_old")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DROP TABLE browser_login_attempts_old")
            .execute(&mut *tx)
            .await?;
        sqlx::query("CREATE INDEX idx_browser_login_attempts_active ON browser_login_attempts(flow, expires_at_unix, consumed_at_unix)").execute(&mut *tx).await?;
        sqlx::query("INSERT INTO schema_migrations(version,name,applied_at_unix) VALUES (10,'public_operator_session_purposes',?)").bind(unix_now_i64()).execute(&mut *tx).await?;
    }
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
    let automation_credential_count = count_rows(pool, "automation_credentials").await?;
    let project_membership_count = count_rows(pool, "project_memberships").await?;
    let permission_request_count = count_rows(pool, "permission_requests").await?;

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
    body.push_str(&format!(
        "project_memberships = {project_membership_count}\n"
    ));
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
    body.push_str(&format!(
        "automation_credentials = {automation_credential_count}\n"
    ));
    body.push_str(&format!(
        "permission_requests = {permission_request_count}\n"
    ));
    Ok(body)
}

pub(crate) async fn count_rows(pool: &SqlitePool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = match table {
        "project_memberships" => "SELECT COUNT(*) FROM project_memberships",
        "profiles" => "SELECT COUNT(*) FROM profiles",
        "steam_accounts" => "SELECT COUNT(*) FROM steam_accounts",
        "github_accounts" => "SELECT COUNT(*) FROM github_accounts",
        "profile_roles" => "SELECT COUNT(*) FROM profile_roles",
        "audit_events" => "SELECT COUNT(*) FROM audit_events",
        "auth_attempts" => "SELECT COUNT(*) FROM auth_attempts",
        "identity_sessions" => "SELECT COUNT(*) FROM identity_sessions",
        "browser_login_attempts" => "SELECT COUNT(*) FROM browser_login_attempts",
        "automation_credentials" => "SELECT COUNT(*) FROM automation_credentials",
        "permission_requests" => "SELECT COUNT(*) FROM permission_requests",
        _ => unreachable!("table name is constrained by caller"),
    };
    sqlx::query_scalar(sql).fetch_one(pool).await
}

#[cfg(test)]
mod project_migration_tests {
    use super::*;
    #[tokio::test]
    async fn project_membership_migration_is_idempotent_and_constrains_roles() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO profiles(id, created_at_unix) VALUES ('actor', 1), ('subject', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO project_memberships(project_id, profile_id, role, version, granted_by_profile_id, granted_at_unix) VALUES ('ghf-studios/loo-cast', 'subject', 'viewer', 1, 'actor', 1)").execute(&pool).await.expect("membership table exists");
        assert!(sqlx::query("UPDATE project_memberships SET role = 'root'")
            .execute(&pool)
            .await
            .is_err());
        let export = export_identity_state(&pool, Path::new("identity.sqlite3"))
            .await
            .unwrap();
        assert!(export.contains("project_memberships = 1"));
    }
    #[tokio::test]
    async fn session_split_migration_preserves_legacy_operator_sessions_and_attempts() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE profiles(id TEXT PRIMARY KEY, display_name TEXT, created_at_unix INTEGER NOT NULL, disabled_at_unix INTEGER)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO profiles(id, created_at_unix) VALUES ('legacy', 1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE identity_sessions(token_hash TEXT PRIMARY KEY, session_id TEXT UNIQUE NOT NULL, profile_id TEXT NOT NULL REFERENCES profiles(id), created_at_unix INTEGER NOT NULL, expires_at_unix INTEGER NOT NULL, revoked_at_unix INTEGER)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO identity_sessions VALUES ('hash', 'session', 'legacy', 1, 9999999999, NULL)").execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE browser_login_attempts(state TEXT PRIMARY KEY, flow TEXT NOT NULL CHECK(flow IN ('steam','github')), profile_id TEXT REFERENCES profiles(id), created_at_unix INTEGER NOT NULL, expires_at_unix INTEGER NOT NULL, consumed_at_unix INTEGER)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO browser_login_attempts VALUES ('state', 'steam', NULL, 1, 9999999999, NULL)").execute(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT purpose FROM identity_sessions WHERE session_id = 'session'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            "operator"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM browser_login_attempts WHERE state = 'state' AND flow = 'steam'").fetch_one(&pool).await.unwrap(), 1);
        assert!(sqlx::query("UPDATE identity_sessions SET purpose = 'root'")
            .execute(&pool)
            .await
            .is_err());
        sqlx::query("INSERT INTO browser_login_attempts VALUES ('user-state', 'user-steam', NULL, 1, 9999999999, NULL)").execute(&pool).await.unwrap();
    }
}
