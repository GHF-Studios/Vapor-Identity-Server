use crate::profiles::current_profile_from_headers;
use crate::types::AppState;
use crate::util::{
    authorization_service_authorized, hash_session_token, html_escape, same_origin_browser_request,
    unix_now_i64,
};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectListRequest {
    audience: String,
    session_token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectCheckRequest {
    audience: String,
    session_token: String,
    project_id: String,
    minimum_role: String,
}
#[derive(Serialize)]
struct Membership {
    project_id: String,
    role: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipChange {
    project_id: String,
    profile_id: String,
    role: String,
    expected_version: i64,
    #[serde(default)]
    confirmed: bool,
}

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("cache-control", "private, no-store".parse().unwrap());
    response
}
fn role_rank(role: &str) -> Option<u8> {
    match role {
        "viewer" => Some(1),
        "developer" => Some(2),
        "owner" => Some(3),
        _ => None,
    }
}
fn valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn valid_project_id(id: &str) -> bool {
    let component = |value: &str| {
        (1..=63).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    };
    id.split_once('/')
        .is_some_and(|(namespace, slug)| component(namespace) && component(slug))
}

async fn session(
    state: &AppState,
    headers: &HeaderMap,
    audience: &str,
    token: &str,
) -> Result<(String, i64), StatusCode> {
    if audience != "vapor-registry" {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !authorization_service_authorized(
        headers,
        state.config.authorization_service_token.as_deref(),
    ) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !(32..=256).contains(&token.len()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let now = unix_now_i64();
    let row = sqlx::query("SELECT s.profile_id, s.expires_at_unix FROM identity_sessions s JOIN profiles p ON p.id = s.profile_id WHERE s.token_hash = ? AND s.expires_at_unix > ? AND s.revoked_at_unix IS NULL AND p.disabled_at_unix IS NULL")
        .bind(hash_session_token(token)).bind(now).fetch_optional(&state.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.ok_or(StatusCode::UNAUTHORIZED)?;
    Ok((
        row.get("profile_id"),
        row.get::<i64, _>("expires_at_unix").min(now + 30),
    ))
}

pub(crate) async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProjectListRequest>,
) -> Response {
    private(match list(&state, &headers, &request).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    })
}
async fn list(
    state: &AppState,
    headers: &HeaderMap,
    request: &ProjectListRequest,
) -> Result<Response, StatusCode> {
    let (profile_id, expires_at_unix) =
        session(state, headers, &request.audience, &request.session_token).await?;
    let memberships: Vec<Membership> = sqlx::query("SELECT project_id, role FROM project_memberships WHERE profile_id = ? AND revoked_at_unix IS NULL ORDER BY project_id")
        .bind(profile_id).fetch_all(&state.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.into_iter().map(|r| Membership { project_id: r.get("project_id"), role: r.get("role") }).collect();
    Ok(
        Json(serde_json::json!({ "memberships": memberships, "expires_at_unix": expires_at_unix }))
            .into_response(),
    )
}
pub(crate) async fn check_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProjectCheckRequest>,
) -> Response {
    private(match check(&state, &headers, &request).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    })
}
async fn check(
    state: &AppState,
    headers: &HeaderMap,
    request: &ProjectCheckRequest,
) -> Result<Response, StatusCode> {
    let (profile_id, expires_at_unix) =
        session(state, headers, &request.audience, &request.session_token).await?;
    let minimum = role_rank(&request.minimum_role)
        .filter(|_| valid_project_id(&request.project_id))
        .ok_or(StatusCode::BAD_REQUEST)?;
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM project_memberships WHERE project_id = ? AND profile_id = ? AND revoked_at_unix IS NULL").bind(&request.project_id).bind(profile_id).fetch_optional(&state.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let allowed = role
        .as_deref()
        .and_then(role_rank)
        .is_some_and(|rank| rank >= minimum);
    let mut body = serde_json::json!({ "allowed": allowed, "expires_at_unix": expires_at_unix });
    if let Some(role) = role {
        body["role"] = role.into();
    }
    Ok(Json(body).into_response())
}
async fn root_actor(
    state: &AppState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<String, StatusCode> {
    let profile = current_profile_from_headers(&state.pool, headers)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !profile.root_authorized
        || (mutation && !same_origin_browser_request(headers, &state.config))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(profile.profile_id)
}

pub(crate) async fn grant_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(change): Json<MembershipChange>,
) -> Response {
    change_response(&state, &headers, &change, false).await
}
pub(crate) async fn revoke_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(change): Json<MembershipChange>,
) -> Response {
    change_response(&state, &headers, &change, true).await
}
async fn change_response(
    state: &AppState,
    headers: &HeaderMap,
    change: &MembershipChange,
    revoke: bool,
) -> Response {
    private(match apply(state, headers, change, revoke).await {
        Ok((version, changed)) => {
            Json(serde_json::json!({"version": version, "changed": changed})).into_response()
        }
        Err(status) => status.into_response(),
    })
}
async fn apply(
    state: &AppState,
    headers: &HeaderMap,
    change: &MembershipChange,
    revoke: bool,
) -> Result<(i64, bool), StatusCode> {
    let actor = root_actor(state, headers, true).await?;
    if !change.confirmed
        || !valid_project_id(&change.project_id)
        || !valid_profile_id(&change.profile_id)
        || role_rank(&change.role).is_none()
        || change.expected_version < 0
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    mutate(&state.pool, &actor, change, revoke).await
}
async fn mutate(
    pool: &SqlitePool,
    actor: &str,
    change: &MembershipChange,
    revoke: bool,
) -> Result<(i64, bool), StatusCode> {
    let db_error = |_| StatusCode::SERVICE_UNAVAILABLE;
    let mut tx = pool.begin().await.map_err(db_error)?;
    // Acquire SQLite's write lock before reading the expected version.
    sqlx::query("UPDATE service_metadata SET value = value WHERE key = 'permission_mutation_lock'")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM profiles WHERE id = ? AND (? OR disabled_at_unix IS NULL))",
    )
    .bind(&change.profile_id)
    .bind(revoke)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_error)?;
    if exists == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    let existing = sqlx::query("SELECT version, role, revoked_at_unix FROM project_memberships WHERE project_id = ? AND profile_id = ?").bind(&change.project_id).bind(&change.profile_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    let version = existing.as_ref().map_or(0, |r| r.get::<i64, _>("version"));
    if version != change.expected_version {
        return Err(StatusCode::CONFLICT);
    }
    if revoke && existing.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    if let Some(row) = existing.as_ref() {
        let same_role = row.get::<String, _>("role") == change.role;
        if revoke && !same_role {
            return Err(StatusCode::CONFLICT);
        }
        if same_role && row.get::<Option<i64>, _>("revoked_at_unix").is_some() == revoke {
            return Ok((version, false));
        }
    }
    let next_version = version.checked_add(1).ok_or(StatusCode::CONFLICT)?;
    let now = unix_now_i64();
    if revoke {
        sqlx::query("UPDATE project_memberships SET revoked_by_profile_id = ?, revoked_at_unix = ?, version = ? WHERE project_id = ? AND profile_id = ?").bind(actor).bind(now).bind(next_version).bind(&change.project_id).bind(&change.profile_id).execute(&mut *tx).await.map_err(db_error)?;
    } else {
        sqlx::query("INSERT INTO project_memberships(project_id, profile_id, role, version, granted_by_profile_id, granted_at_unix) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, profile_id) DO UPDATE SET role = excluded.role, version = excluded.version, granted_by_profile_id = excluded.granted_by_profile_id, granted_at_unix = excluded.granted_at_unix, revoked_by_profile_id = NULL, revoked_at_unix = NULL")
            .bind(&change.project_id).bind(&change.profile_id).bind(&change.role).bind(next_version).bind(actor).bind(now).execute(&mut *tx).await.map_err(db_error)?;
    }
    let event = if revoke {
        "project_membership_revoked"
    } else {
        "project_membership_granted"
    };
    let detail = serde_json::json!({"project_id": change.project_id, "role": change.role, "previous_role": existing.as_ref().map(|r| r.get::<String,_>("role")), "version": next_version}).to_string();
    sqlx::query("INSERT INTO audit_events(event_type, actor_profile_id, subject_profile_id, created_at_unix, detail) VALUES (?, ?, ?, ?, ?)").bind(event).bind(actor).bind(&change.profile_id).bind(now).bind(detail).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok((next_version, true))
}

pub(crate) async fn grant_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(change): Form<MembershipChange>,
) -> Response {
    form_response(&state, &headers, &change, false).await
}
pub(crate) async fn revoke_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(change): Form<MembershipChange>,
) -> Response {
    form_response(&state, &headers, &change, true).await
}
async fn form_response(
    state: &AppState,
    headers: &HeaderMap,
    change: &MembershipChange,
    revoke: bool,
) -> Response {
    private(match apply(state, headers, change, revoke).await { Ok(_) => Redirect::to("/admin/identity/project-memberships").into_response(), Err(status) => (status, "Membership change rejected. Refresh the membership page and review the current version.").into_response() })
}
pub(crate) async fn membership_fragment(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = root_actor(&state, &headers, false).await {
        return private(status.into_response());
    }
    let rows = match sqlx::query("SELECT project_id, profile_id, role, version, revoked_at_unix FROM project_memberships ORDER BY project_id, profile_id").fetch_all(&state.pool).await { Ok(rows) => rows, Err(_) => return private(StatusCode::SERVICE_UNAVAILABLE.into_response()) };
    let mut body = String::from("<h1>Project memberships</h1><p>Project IDs come from Registry. Global roles do not grant Project access. Use version 0 for a new membership; otherwise use the version below.</p><form method=\"post\" action=\"/admin/identity/project-memberships/grant\"><label>Project ID <input name=\"project_id\" maxlength=\"127\" pattern=\"[a-z0-9_-]{1,63}/[a-z0-9_-]{1,63}\" required></label><label>Profile ID <input name=\"profile_id\" maxlength=\"128\" required></label><label>Role <select name=\"role\"><option>viewer</option><option>developer</option><option>owner</option></select></label><label>Expected version <input type=\"number\" name=\"expected_version\" min=\"0\" value=\"0\" required></label><label><input type=\"checkbox\" name=\"confirmed\" value=\"true\" required> Confirm grant</label><button>Grant membership</button></form><table><thead><tr><th>Project</th><th>Profile</th><th>Role</th><th>Version</th><th>Status</th><th>Action</th></tr></thead><tbody>");
    for row in rows {
        let project = html_escape(&row.get::<String, _>("project_id"));
        let profile = html_escape(&row.get::<String, _>("profile_id"));
        let role = html_escape(&row.get::<String, _>("role"));
        let version: i64 = row.get("version");
        let revoked = row.get::<Option<i64>, _>("revoked_at_unix").is_some();
        let action = if revoked {
            String::new()
        } else {
            format!("<form method=\"post\" action=\"/admin/identity/project-memberships/revoke\"><input type=\"hidden\" name=\"project_id\" value=\"{project}\"><input type=\"hidden\" name=\"profile_id\" value=\"{profile}\"><input type=\"hidden\" name=\"role\" value=\"{role}\"><input type=\"hidden\" name=\"expected_version\" value=\"{version}\"><label><input type=\"checkbox\" name=\"confirmed\" value=\"true\" required> Confirm revoke</label><button>Revoke</button></form>")
        };
        body.push_str(&format!("<tr><td>{project}</td><td>{profile}</td><td>{role}</td><td>{version}</td><td>{}</td><td>{action}</td></tr>", if revoked { "revoked" } else { "active" }));
    }
    body.push_str("</tbody></table>");
    crate::browser_handlers::admin_fragment_response(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::AuthConfig, db::run_migrations, profiles::create_identity_session};
    use axum::body::to_bytes;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::Arc;

    async fn state() -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(":memory:")
                    .foreign_keys(true),
            )
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO profiles(id, created_at_unix) VALUES ('actor', 1), ('subject', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        AppState {
            pool,
            db_path: Arc::new("identity.sqlite3".into()),
            admin_token: Some("admin-token".into()),
            platform_request_authz_token: None,
            config: Arc::new(AuthConfig {
                steam_app_id: 1,
                steam_auth_identity: String::new(),
                steam_web_api_key: None,
                loocast_app_id: 1,
                authorization_service_token: Some("registry-token".into()),
                platform_admin_authorization_service_token: Some("platform-token".into()),
                artifact_admin_authorization_service_token: None,
                build_cache_admin_authorization_service_token: None,
                github_client_id: None,
                github_client_secret: None,
                dashboard_password: None,
                cookie_secure: true,
                cookie_path: "/".into(),
                public_origin: Some("https://vapor.example".into()),
            }),
            http: reqwest::Client::new(),
        }
    }
    fn change(role: &str, version: i64) -> MembershipChange {
        MembershipChange {
            project_id: "ghf-studios/loo-cast".into(),
            profile_id: "subject".into(),
            role: role.into(),
            expected_version: version,
            confirmed: true,
        }
    }
    fn service_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }
    async fn json(response: Response) -> serde_json::Value {
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        serde_json::from_slice(&to_bytes(response.into_body(), 100000).await.unwrap()).unwrap()
    }
    async fn root_headers(state: &AppState) -> HeaderMap {
        sqlx::query("INSERT INTO steam_accounts VALUES ('76561198123456789', 'actor', 1, 1)")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO github_accounts VALUES (1, 'rootdev', 'actor', 1, 1)")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO profile_roles VALUES ('actor', 'root', 1, NULL)")
            .execute(&state.pool)
            .await
            .unwrap();
        let (_, token, _) = create_identity_session(&state.pool, "actor").await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("vapor_identity_session={token}").parse().unwrap(),
        );
        headers.insert("origin", "https://vapor.example".parse().unwrap());
        headers
    }
    #[tokio::test]
    async fn grant_revoke_regrant_are_versioned_idempotent_and_audited() {
        let s = state().await;
        assert_eq!(
            mutate(&s.pool, "actor", &change("viewer", 0), false)
                .await
                .unwrap(),
            (1, true)
        );
        assert_eq!(
            mutate(&s.pool, "actor", &change("viewer", 1), false)
                .await
                .unwrap(),
            (1, false)
        );
        assert!(mutate(&s.pool, "actor", &change("owner", 0), false)
            .await
            .is_err());
        assert_eq!(
            mutate(&s.pool, "actor", &change("viewer", 1), true)
                .await
                .unwrap(),
            (2, true)
        );
        assert_eq!(
            mutate(&s.pool, "actor", &change("owner", 2), false)
                .await
                .unwrap(),
            (3, true)
        );
        let rows = sqlx::query("SELECT event_type, actor_profile_id, subject_profile_id, detail FROM audit_events ORDER BY id").fetch_all(&s.pool).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[1].get::<String, _>("event_type"),
            "project_membership_revoked"
        );
        for row in rows {
            assert_eq!(row.get::<String, _>("actor_profile_id"), "actor");
            assert_eq!(row.get::<String, _>("subject_profile_id"), "subject");
            assert!(row
                .get::<String, _>("detail")
                .contains("ghf-studios/loo-cast"));
        }
    }
    #[tokio::test]
    async fn live_session_and_registry_credential_are_required_and_global_roles_grant_nothing() {
        let s = state().await;
        let _ = root_headers(&s).await;
        let (_, token, expiry) = create_identity_session(&s.pool, "actor").await.unwrap();
        let request = || ProjectListRequest {
            audience: "vapor-registry".into(),
            session_token: token.clone(),
        };
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("platform-token"),
                Json(request())
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let data = json(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(request()),
            )
            .await,
        )
        .await;
        assert_eq!(data["memberships"], serde_json::json!([]));
        assert!(data["expires_at_unix"].as_i64().unwrap() <= expiry);
        sqlx::query("UPDATE identity_sessions SET revoked_at_unix = 1")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(request())
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn checks_apply_role_hierarchy_project_boundary_and_revocation() {
        let s = state().await;
        mutate(&s.pool, "actor", &change("developer", 0), false)
            .await
            .unwrap();
        let (_, token, _) = create_identity_session(&s.pool, "subject").await.unwrap();
        for (project, minimum, expected) in [
            ("ghf-studios/loo-cast", "viewer", true),
            ("ghf-studios/loo-cast", "owner", false),
            ("ghf-studios/mad-max-modding", "viewer", false),
        ] {
            let result = json(
                check_project(
                    State(s.clone()),
                    service_headers("registry-token"),
                    Json(ProjectCheckRequest {
                        audience: "vapor-registry".into(),
                        session_token: token.clone(),
                        project_id: project.into(),
                        minimum_role: minimum.into(),
                    }),
                )
                .await,
            )
            .await;
            assert_eq!(result["allowed"], expected);
        }
        mutate(&s.pool, "actor", &change("developer", 1), true)
            .await
            .unwrap();
        let result = json(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(ProjectListRequest {
                    audience: "vapor-registry".into(),
                    session_token: token,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(result["memberships"], serde_json::json!([]));
    }
    #[tokio::test]
    async fn admin_mutations_require_root_origin_confirmation_and_valid_inputs() {
        let s = state().await;
        assert_eq!(
            grant_membership(
                State(s.clone()),
                HeaderMap::new(),
                Json(change("viewer", 0))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut headers = root_headers(&s).await;
        headers.insert("origin", "https://evil.example".parse().unwrap());
        assert_eq!(
            grant_membership(State(s.clone()), headers.clone(), Json(change("viewer", 0)))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.insert("origin", "https://vapor.example".parse().unwrap());
        let mut c = change("viewer", 0);
        c.confirmed = false;
        assert_eq!(
            grant_membership(State(s.clone()), headers.clone(), Json(c))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            grant_membership(State(s.clone()), headers.clone(), Json(change("root", 0)))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut c = change("viewer", 0);
        c.project_id = "<script>".into();
        assert_eq!(
            grant_membership(State(s.clone()), headers.clone(), Json(c))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            grant_membership(State(s.clone()), headers.clone(), Json(change("viewer", 0)))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            grant_membership(State(s.clone()), headers.clone(), Json(change("owner", 0)))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            revoke_membership(State(s.clone()), headers.clone(), Json(change("viewer", 1)))
                .await
                .status(),
            StatusCode::OK
        );
        let html = membership_fragment(State(s.clone()), headers).await;
        assert_eq!(html.status(), StatusCode::OK);
        assert_eq!(
            html.headers()["content-type"],
            "application/vnd.vapor.admin-page.v1+html; charset=utf-8"
        );
        let html =
            String::from_utf8(to_bytes(html.into_body(), 100000).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("ghf-studios/loo-cast"));
        assert!(html.contains("expected_version"));
    }
    #[tokio::test]
    async fn sqlite_snapshot_roundtrip_preserves_active_revoked_memberships_and_audit() {
        let s = state().await;
        mutate(&s.pool, "actor", &change("viewer", 0), false)
            .await
            .unwrap();
        mutate(&s.pool, "actor", &change("viewer", 1), true)
            .await
            .unwrap();
        let mut active = change("owner", 0);
        active.project_id = "ghf-studios/mad-max-modding".into();
        mutate(&s.pool, "actor", &active, false).await.unwrap();
        let path = std::env::temp_dir().join(format!(
            "identity-project-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        sqlx::query("VACUUM INTO ?")
            .bind(path.to_str().unwrap())
            .execute(&s.pool)
            .await
            .unwrap();
        let restored = crate::db::open_database(&path).await.unwrap();
        run_migrations(&restored).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM project_memberships WHERE revoked_at_unix IS NULL"
            )
            .fetch_one(&restored)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM project_memberships WHERE revoked_at_unix IS NOT NULL"
            )
            .fetch_one(&restored)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
                .fetch_one(&restored)
                .await
                .unwrap(),
            3
        );
        restored.close().await;
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn invalid_expired_disabled_and_unavailable_sessions_fail_closed() {
        let s = state().await;
        let (_, token, _) = create_identity_session(&s.pool, "subject").await.unwrap();
        let call = |audience: &str, session_token: String| ProjectListRequest {
            audience: audience.into(),
            session_token,
        };
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(call("vapor-platform-admin", token.clone()))
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(call("vapor-registry", "short".into()))
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        sqlx::query("UPDATE identity_sessions SET expires_at_unix = 1")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(call("vapor-registry", token))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let (_, token, _) = create_identity_session(&s.pool, "subject").await.unwrap();
        sqlx::query("UPDATE profiles SET disabled_at_unix = 1 WHERE id = 'subject'")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(call("vapor-registry", token.clone()))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        s.pool.close().await;
        assert_eq!(
            list_projects(
                State(s.clone()),
                service_headers("registry-token"),
                Json(call("vapor-registry", token))
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn admin_service_tokens_and_nonroot_sessions_cannot_grant() {
        let s = state().await;
        let mut h = service_headers("admin-token");
        h.insert("origin", "https://vapor.example".parse().unwrap());
        assert_eq!(
            grant_membership(State(s.clone()), h, Json(change("viewer", 0)))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let (_, token, _) = create_identity_session(&s.pool, "subject").await.unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            format!("vapor_identity_session={token}").parse().unwrap(),
        );
        h.insert("origin", "https://vapor.example".parse().unwrap());
        assert_eq!(
            grant_membership(State(s.clone()), h, Json(change("viewer", 0)))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn malformed_membership_http_requests_are_private_and_bad_requests() {
        let s = state().await;
        let app = axum::Router::new()
            .route(
                "/v1/internal/projects/list",
                axum::routing::post(list_projects),
            )
            .route_layer(axum::middleware::from_fn(crate::no_store_admin_responses))
            .with_state(s);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let response = reqwest::Client::new().post(format!("http://{addr}/v1/internal/projects/list")).json(&serde_json::json!({"audience": "vapor-registry", "session_token": "short", "unexpected": true})).send().await.unwrap();
        let status = response.status();
        let cache = response.headers()["cache-control"].clone();
        server.abort();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(cache, "private, no-store");
    }
    #[tokio::test]
    async fn audit_failure_rolls_back_the_membership_change() {
        let s = state().await;
        sqlx::query("CREATE TRIGGER reject_project_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END").execute(&s.pool).await.unwrap();
        assert_eq!(
            mutate(&s.pool, "actor", &change("viewer", 0), false)
                .await
                .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM project_memberships")
                .fetch_one(&s.pool)
                .await
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn disabled_profiles_can_be_revoked_but_not_granted() {
        let s = state().await;
        let h = root_headers(&s).await;
        assert_eq!(
            grant_membership(State(s.clone()), h.clone(), Json(change("viewer", 0)))
                .await
                .status(),
            StatusCode::OK
        );
        sqlx::query("UPDATE profiles SET disabled_at_unix = 1 WHERE id = 'subject'")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(
            revoke_membership(State(s.clone()), h.clone(), Json(change("viewer", 1)))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            grant_membership(State(s.clone()), h, Json(change("viewer", 2)))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn actual_project_ids_are_accepted_with_bounded_single_separator() {
        let s = state().await;
        let h = root_headers(&s).await;
        let response =
            grant_membership(State(s.clone()), h.clone(), Json(change("viewer", 0))).await;
        assert_eq!(response.status(), StatusCode::OK);
        for id in [
            "ghf-studios//loo-cast",
            "/loo-cast",
            "ghf-studios/",
            "ghf-studios/loo-cast/more",
            "ghf-studios/<script>",
        ] {
            let mut c = change("viewer", 0);
            c.project_id = id.into();
            assert_eq!(
                grant_membership(State(s.clone()), h.clone(), Json(c))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
    }
}
