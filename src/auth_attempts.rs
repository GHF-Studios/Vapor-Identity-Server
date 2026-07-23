use sqlx::{Row, SqlitePool};

use crate::types::GitHubUser;
use crate::util::{new_profile_id, unix_now_i64};

pub(crate) struct BrowserLoginAttempt {
    pub(crate) profile_id: Option<String>,
}

pub(crate) async fn create_browser_login_attempt(
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

pub(crate) async fn browser_login_attempt(
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

pub(crate) async fn consume_browser_login_attempt(
    pool: &SqlitePool,
    state: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE browser_login_attempts SET consumed_at_unix = ? WHERE state = ?")
        .bind(unix_now_i64())
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn create_auth_attempt(
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

pub(crate) async fn prune_expired_auth_state(
    pool: &SqlitePool,
    now: i64,
) -> Result<(), sqlx::Error> {
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

pub(crate) async fn auth_attempt_is_active(
    pool: &SqlitePool,
    id: &str,
) -> Result<bool, sqlx::Error> {
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

pub(crate) async fn record_auth_attempt_steam(
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

pub(crate) async fn record_auth_attempt_github(
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

pub(crate) async fn record_github_device_flow(
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

pub(crate) struct GitHubDeviceFlow {
    pub(crate) device_code: String,
    pub(crate) interval_seconds: i64,
    pub(crate) next_poll_at_unix: i64,
}

pub(crate) async fn github_device_flow(
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

pub(crate) async fn update_github_device_poll(
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

pub(crate) async fn clear_github_device_flow(
    pool: &SqlitePool,
    id: &str,
) -> Result<(), sqlx::Error> {
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

pub(crate) struct LinkedProfile {
    pub(crate) profile_id: String,
    pub(crate) steam_id64: String,
    pub(crate) github_login: String,
}

pub(crate) enum AuthFinishError {
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

pub(crate) async fn link_verified_auth_attempt(
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

pub(crate) async fn consume_auth_attempt(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE auth_attempts SET consumed_at_unix = ? WHERE id = ?")
        .bind(unix_now_i64())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
