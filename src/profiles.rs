use axum::http::HeaderMap;
use sqlx::{Row, SqlitePool};

use crate::config::DASHBOARD_SESSION_TTL_SECONDS;
use crate::types::{AppState, GitHubUser};
use crate::util::{
    authorized, csv_values, first_csv, hash_session_token, new_profile_id, new_session_id,
    new_session_token, session_token_from_headers, toml_string, unix_now_i64,
};

pub(crate) async fn profile_has_dual_identity(
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

pub(crate) async fn profile_has_root_role(
    pool: &SqlitePool,
    profile_id: &str,
) -> Result<bool, sqlx::Error> {
    profile_has_role(pool, profile_id, "root").await
}

pub(crate) async fn profile_has_role(
    pool: &SqlitePool,
    profile_id: &str,
    role: &str,
) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS (
            SELECT 1 FROM profile_roles
            WHERE profile_id = ?
              AND role = ?
              AND revoked_at_unix IS NULL
        )",
    )
    .bind(profile_id)
    .bind(role)
    .fetch_one(pool)
    .await?;
    Ok(exists == 1)
}

pub(crate) async fn active_root_profile_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT profile_id)
         FROM profile_roles
         WHERE role = 'root' AND revoked_at_unix IS NULL",
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn grant_root(
    pool: &SqlitePool,
    profile_id: &str,
    actor_profile_id: Option<&str>,
) -> Result<bool, sqlx::Error> {
    grant_role(pool, profile_id, "root", actor_profile_id).await
}

pub(crate) fn valid_elevated_role(role: &str) -> bool {
    matches!(role, "root" | "content-developer")
}

pub(crate) async fn grant_role(
    pool: &SqlitePool,
    profile_id: &str,
    role: &str,
    actor_profile_id: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let now = unix_now_i64();
    let already_active = profile_has_role(pool, profile_id, role).await?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO profile_roles (profile_id, role, granted_at_unix, revoked_at_unix)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT(profile_id, role) DO UPDATE
         SET granted_at_unix = excluded.granted_at_unix,
             revoked_at_unix = NULL",
    )
    .bind(profile_id)
    .bind(role)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let event_type = if role == "root" {
        "root_role_granted"
    } else {
        "profile_role_granted"
    };
    let detail = if role == "root" {
        String::new()
    } else {
        format!("role={role}")
    };
    sqlx::query(
        "INSERT INTO audit_events (event_type, actor_profile_id, subject_profile_id, created_at_unix, detail)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(event_type)
    .bind(actor_profile_id)
    .bind(profile_id)
    .bind(now)
    .bind(detail)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(!already_active)
}

pub(crate) async fn create_identity_session(
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

pub(crate) struct CurrentProfile {
    pub(crate) profile_id: String,
    pub(crate) display_name: Option<String>,
    pub(crate) steam_id64: Option<String>,
    pub(crate) github_login: Option<String>,
    pub(crate) roles: Vec<String>,
    pub(crate) root_authorized: bool,
}

pub(crate) async fn current_profile_from_headers(
    pool: &SqlitePool,
    headers: &HeaderMap,
) -> Result<Option<CurrentProfile>, sqlx::Error> {
    let Some(profile_id) = session_profile_id(pool, headers).await? else {
        return Ok(None);
    };
    profile_by_id(pool, &profile_id).await
}

pub(crate) async fn session_profile_id(
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

pub(crate) async fn profile_by_id(
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
    let roles = effective_roles(roles);
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

pub(crate) async fn profile_id_by_linked_identities(
    pool: &SqlitePool,
    steam_id64: &str,
    github_login: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT p.id
         FROM profiles p
         JOIN steam_accounts s ON s.profile_id = p.id
         JOIN github_accounts g ON g.profile_id = p.id
         WHERE s.steam_id64 = ?
           AND lower(g.github_login) = lower(?)
           AND p.disabled_at_unix IS NULL",
    )
    .bind(steam_id64)
    .bind(github_login)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn revoke_identity_session(
    pool: &SqlitePool,
    token: &str,
) -> Result<(), sqlx::Error> {
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

pub(crate) async fn root_session_profile_id(
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

pub(crate) async fn admin_or_root_authorized(
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

pub(crate) async fn active_roles(
    pool: &SqlitePool,
    profile_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT role FROM profile_roles
         WHERE profile_id = ? AND revoked_at_unix IS NULL
         ORDER BY role",
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await?;
    Ok(effective_roles(rows))
}

pub(crate) fn effective_roles(mut roles: Vec<String>) -> Vec<String> {
    if roles.iter().any(|role| role == "root") {
        roles.push("content-developer".to_string());
    }
    roles.sort();
    roles.dedup();
    roles
}

pub(crate) async fn link_steam_account(
    pool: &SqlitePool,
    steam_id64: &str,
) -> Result<String, sqlx::Error> {
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

pub(crate) async fn link_github_account_to_profile(
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

pub(crate) struct ProfileRow {
    pub(crate) profile_id: String,
    pub(crate) display_name: Option<String>,
    pub(crate) steam_ids: Option<String>,
    pub(crate) github_logins: Option<String>,
    pub(crate) roles: Option<String>,
}

pub(crate) async fn profile_rows(pool: &SqlitePool) -> Result<Vec<ProfileRow>, sqlx::Error> {
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

pub(crate) async fn profile_listing(pool: &SqlitePool) -> Result<String, sqlx::Error> {
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
