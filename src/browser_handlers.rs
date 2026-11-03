use axum::body::to_bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use axum::Json;
use serde::Deserialize;
use sqlx::Row;
use std::collections::HashMap;

#[derive(Deserialize)]
pub(crate) struct AutomationCredentialForm {
    label: String,
    expires_in_days: i64,
    #[serde(default)]
    scopes: Vec<String>,
}

use crate::automation_credentials::{
    create_automation_credential, revoke_automation_credential, CreateAutomationCredentialRequest,
};
use crate::config::{
    BROWSER_LOGIN_ATTEMPT_TTL_SECONDS, DASHBOARD_SESSION_TTL_SECONDS, STEAM_OPENID_ENDPOINT,
};
use crate::permission_requests::{
    approve_permission_request, create_permission_request, reject_permission_request,
    ApprovePermissionRequest, CreatePermissionRequest, RejectPermissionRequest,
};
use crate::persistence::*;
use crate::providers::{exchange_github_web_code, verify_github_access_token, verify_steam_openid};
use crate::types::*;
use crate::util::{
    admin_locked_html, expired_session_cookie, github_browser_ready, html_escape, login_html,
    new_browser_login_state, percent_encode, public_origin, redirect_response,
    redirect_with_cookie, same_origin_browser_request, session_token_from_headers, text_response,
    unix_now_i64, valid_browser_state,
};

pub(crate) async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to load login state: {error}\n"),
            )
                .into_response();
        }
    };

    Html(login_html(&state.config, current.as_ref())).into_response()
}

pub(crate) async fn login_steam_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let state_token = new_browser_login_state();
    let now = unix_now_i64();
    if let Err(error) = create_browser_login_attempt(
        &state.pool,
        &state_token,
        "steam",
        None,
        now,
        now + BROWSER_LOGIN_ATTEMPT_TTL_SECONDS,
    )
    .await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to start Steam login: {error}"),
        );
    }

    let origin = public_origin(&state.config, &headers);
    let return_to = format!("{origin}/login/steam/callback?state={state_token}");
    let redirect = format!(
        "{STEAM_OPENID_ENDPOINT}?openid.ns={}&openid.mode=checkid_setup&openid.claimed_id={}&openid.identity={}&openid.return_to={}&openid.realm={}",
        percent_encode("http://specs.openid.net/auth/2.0"),
        percent_encode("http://specs.openid.net/auth/2.0/identifier_select"),
        percent_encode("http://specs.openid.net/auth/2.0/identifier_select"),
        percent_encode(&return_to),
        percent_encode(&format!("{origin}/")),
    );

    redirect_response(&redirect)
}

pub(crate) async fn login_steam_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(state_token) = params
        .get("state")
        .filter(|value| valid_browser_state(value))
    else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: missing or invalid state",
        );
    };
    match browser_login_attempt(&state.pool, state_token, "steam").await {
        Ok(Some(_attempt)) => {}
        Ok(None) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: Steam login attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read Steam login attempt: {error}"),
            );
        }
    }

    let origin = public_origin(&state.config, &headers);
    let expected_return_to = format!("{origin}/login/steam/callback?state={state_token}");
    if params
        .get("openid.return_to")
        .is_none_or(|return_to| return_to != &expected_return_to)
    {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID return_to did not match login attempt",
        );
    }

    let steam_id64 = match verify_steam_openid(&state.http, &params).await {
        Ok(steam_id64) => steam_id64,
        Err(response) => return response,
    };
    let profile_id = match link_steam_account(&state.pool, &steam_id64).await {
        Ok(profile_id) => profile_id,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to persist Steam profile: {error}"),
            );
        }
    };
    let (_session_id, token, _expires_at_unix) =
        match create_identity_session(&state.pool, &profile_id).await {
            Ok(session) => session,
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to create login session: {error}"),
                );
            }
        };
    if let Err(error) = consume_browser_login_attempt(&state.pool, state_token).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to consume Steam login attempt: {error}"),
        );
    }

    redirect_with_cookie(&state.config, "/login", &token)
}

pub(crate) async fn login_github_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !github_browser_ready(&state.config) {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub browser login is not configured",
        );
    }
    let Some(profile) = (match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to load login state: {error}"),
            );
        }
    }) else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: sign in with Steam before linking GitHub",
        );
    };

    let state_token = new_browser_login_state();
    let now = unix_now_i64();
    if let Err(error) = create_browser_login_attempt(
        &state.pool,
        &state_token,
        "github",
        Some(&profile.profile_id),
        now,
        now + BROWSER_LOGIN_ATTEMPT_TTL_SECONDS,
    )
    .await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to start GitHub login: {error}"),
        );
    }

    let origin = public_origin(&state.config, &headers);
    let redirect_uri = format!("{origin}/login/github/callback");
    let client_id = state.config.github_client_id.as_deref().unwrap_or_default();
    let redirect = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}&allow_signup=true",
        percent_encode(client_id),
        percent_encode(&redirect_uri),
        percent_encode("read:user"),
        percent_encode(&state_token),
    );
    redirect_response(&redirect)
}

pub(crate) async fn login_github_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GitHubCallbackQuery>,
) -> Response {
    if let Some(error) = query.error.as_deref() {
        let detail = query.error_description.as_deref().unwrap_or(error);
        return text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub authorization failed: {detail}"),
        );
    }
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return text_response(StatusCode::BAD_REQUEST, "identity: missing GitHub code");
    };
    let Some(state_token) = query
        .state
        .as_deref()
        .filter(|value| valid_browser_state(value))
    else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: missing or invalid state",
        );
    };
    let Some(client_id) = state.config.github_client_id.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    };
    let Some(client_secret) = state.config.github_client_secret.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client secret is not configured",
        );
    };

    let attempt = match browser_login_attempt(&state.pool, state_token, "github").await {
        Ok(Some(attempt)) => attempt,
        Ok(None) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: GitHub login attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read GitHub login attempt: {error}"),
            );
        }
    };
    let Some(profile_id) = attempt.profile_id else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub browser login must attach to a Steam profile",
        );
    };
    if current_profile_from_headers(&state.pool, &headers)
        .await
        .ok()
        .flatten()
        .is_none_or(|profile| profile.profile_id != profile_id)
    {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub login attempt does not match current Steam session",
        );
    }

    let origin = public_origin(&state.config, &headers);
    let redirect_uri = format!("{origin}/login/github/callback");
    let token =
        match exchange_github_web_code(&state.http, client_id, client_secret, code, &redirect_uri)
            .await
        {
            Ok(token) => token,
            Err(response) => return response,
        };
    let user = match verify_github_access_token(&state.http, &token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let display_name = user.name.as_deref().unwrap_or(&user.login);
    if let Err(error) =
        link_github_account_to_profile(&state.pool, &profile_id, &user, display_name).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to link GitHub identity: {error}"),
        );
    }
    if let Err(error) = consume_browser_login_attempt(&state.pool, state_token).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to consume GitHub login attempt: {error}"),
        );
    }

    redirect_response("/login")
}

pub(crate) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = session_token_from_headers(&headers) {
        if let Err(error) = revoke_identity_session(&state.pool, &token).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to revoke session: {error}\n"),
            )
                .into_response();
        }
    }
    (
        StatusCode::SEE_OTHER,
        [
            (SET_COOKIE, expired_session_cookie(&state.config)),
            (LOCATION, "/login".to_string()),
        ],
        "",
    )
        .into_response()
}

pub(crate) async fn admin_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(profile) => profile,
        Err(_) => {
            return admin_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "identity: failed to validate dashboard session",
            );
        }
    };
    let Some(current) = current else {
        return admin_html_response(admin_locked_html(None));
    };
    if !current.root_authorized {
        return admin_html_response(admin_locked_html(Some(&current)));
    }

    let profile_rows = match profile_rows(&state.pool).await {
        Ok(rows) => rows,
        Err(_) => {
            return admin_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "identity: failed to load dashboard",
            );
        }
    };
    let audit_rows = match recent_audit_events(&state.pool, 25).await {
        Ok(rows) => rows,
        Err(_) => {
            return admin_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "identity: failed to load dashboard audit events",
            );
        }
    };
    let request_rows = match sqlx::query(
        "SELECT id, action, role, steam_id64, github_login, version, created_at_unix, expires_at_unix
         FROM permission_requests WHERE status = 'pending' ORDER BY created_at_unix LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return admin_text_response(StatusCode::INTERNAL_SERVER_ERROR, "identity: failed to load permission requests"),
    };
    let credential_rows = match sqlx::query(
        "SELECT id, label, scopes, created_at_unix, expires_at_unix, revoked_at_unix
         FROM automation_credentials ORDER BY created_at_unix DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            return admin_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "identity: failed to load automation credentials",
            )
        }
    };
    let mut credentials = String::new();
    for row in credential_rows {
        let id: String = row.get("id");
        let revoked_at: Option<i64> = row.get("revoked_at_unix");
        let expires_at: i64 = row.get("expires_at_unix");
        let state_label = if revoked_at.is_some() {
            "revoked"
        } else if expires_at <= unix_now_i64() {
            "expired"
        } else {
            "active"
        };
        let revoke = if state_label == "active" {
            format!("<form class=\"inline\" method=\"post\" action=\"/admin/identity/automation-credentials/{}/revoke\"><button type=\"submit\">Revoke</button></form>", html_escape(&id))
        } else {
            String::new()
        };
        credentials.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{revoke}</td></tr>",
            html_escape(row.get::<String, _>("label").as_str()),
            html_escape(row.get::<String, _>("scopes").as_str()),
            row.get::<i64, _>("created_at_unix"), expires_at, state_label
        ));
    }
    if credentials.is_empty() {
        credentials.push_str("<tr><td colspan=\"6\">No automation credentials.</td></tr>");
    }
    let mut permission_requests = String::new();
    for row in request_rows {
        let id: String = row.get("id");
        let version: i64 = row.get("version");
        permission_requests.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>Steam {} / GitHub {}</td><td>{}</td><td>{}</td><td><form class=\"inline\" method=\"post\" action=\"/admin/identity/permission-requests/{}/approve\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"><label><input type=\"checkbox\" name=\"confirmed\" value=\"true\" required> confirm</label><button type=\"submit\">Approve</button></form><form class=\"inline\" method=\"post\" action=\"/admin/identity/permission-requests/{}/reject\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"><input type=\"hidden\" name=\"reason\" value=\"Rejected by root administrator\"><label><input type=\"checkbox\" name=\"confirmed\" value=\"true\" required> confirm</label><button type=\"submit\">Reject</button></form></td></tr>",
            html_escape(&id),
            html_escape(row.get::<String, _>("action").as_str()),
            html_escape(row.get::<String, _>("role").as_str()),
            html_escape(row.get::<String, _>("steam_id64").as_str()),
            html_escape(row.get::<String, _>("github_login").as_str()),
            row.get::<i64, _>("created_at_unix"),
            row.get::<i64, _>("expires_at_unix"),
            html_escape(&id), version, html_escape(&id), version
        ));
    }
    if permission_requests.is_empty() {
        permission_requests.push_str("<tr><td colspan=\"7\">No pending requests.</td></tr>");
    }
    let mut rows = String::new();
    for row in profile_rows {
        let actions = role_action_forms(&row);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{actions}</td></tr>",
            html_escape(row.display_name.as_deref().unwrap_or("")),
            html_escape(row.steam_ids.as_deref().unwrap_or("")),
            html_escape(row.github_logins.as_deref().unwrap_or("")),
            html_escape(row.roles.as_deref().unwrap_or(""))
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"5\">No profiles yet.</td></tr>");
    }
    let mut audit = String::new();
    for row in audit_rows {
        audit.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            row.event_id,
            row.created_at_unix,
            html_escape(&row.event_type),
            html_escape(&external_identity_label(
                row.actor_steam_ids.as_deref(),
                row.actor_github_logins.as_deref()
            )),
            html_escape(&external_identity_label(
                row.subject_steam_ids.as_deref(),
                row.subject_github_logins.as_deref()
            )),
            html_escape(&row.detail)
        ));
    }
    if audit.is_empty() {
        audit.push_str("<tr><td colspan=\"6\">No audit events yet.</td></tr>");
    }
    let notice = params
        .get("notice")
        .filter(|value| !value.is_empty())
        .map(|value| format!("<p class=\"notice\">{}</p>", html_escape(value)))
        .unwrap_or_default();
    let error = params
        .get("error")
        .filter(|value| !value.is_empty())
        .map(|value| format!("<p class=\"error\">{}</p>", html_escape(value)))
        .unwrap_or_default();

    admin_html_response(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Vapor Identity</title><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\"><script defer src=\"/admin/assets/admin.js\"></script></head><body><main id=\"admin-content\">\
         <p class=\"eyebrow\">Identity</p><h1>Accounts and access</h1>\
         <p>Signed in as Steam profile <code>{}</code>. Root role is active.</p>\
         <p><a href=\"/login\">Identity</a> · <a href=\"/logout\">Logout</a></p>\
         {notice}{error}\
         <h2>Readiness</h2>\
         <ul><li>Steam browser login: <code>true</code></li>\
         <li>GitHub browser login configured: <code>{}</code></li>\
         <li>Dashboard session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <h2>Grant role</h2>\
         <form method=\"post\" action=\"/admin/identity/roles/grant\">\
         <label>Role <select name=\"role\"><option value=\"content-developer\">content-developer</option><option value=\"root\">root</option></select></label>\
         <label>SteamID64 <input name=\"steam_id64\" inputmode=\"numeric\" pattern=\"[0-9]{{17}}\" required></label>\
         <label>GitHub login <input name=\"github_login\" required></label>\
         <button type=\"submit\">Grant role</button></form>\
         <p>This form requires your root dashboard session. It still refuses grants unless the SteamID64 and GitHub login are already linked to the same profile.</p>\
         <p>Root implies content-developer. To demote a root profile to developer, first grant <code>content-developer</code>, then revoke <code>root</code>.</p>\
         <h2>Permission requests</h2><p>Role changes remain pending until approved here by a root session.</p><table><thead><tr><th>Request</th><th>Action</th><th>Role</th><th>Subject</th><th>Created</th><th>Expires</th><th>Decision</th></tr></thead><tbody>{permission_requests}</tbody></table>\
         <h2>Automation request credentials</h2><p>These credentials can submit only the selected request types. Copy the secret from the one-time creation response; it is not stored or shown again.</p><form method=\"post\" action=\"/admin/identity/automation-credentials\"><label>Label <input name=\"label\" maxlength=\"80\" required></label><label>Expires in days <input name=\"expires_in_days\" type=\"number\" min=\"1\" max=\"90\" value=\"30\" required></label><label><input type=\"checkbox\" name=\"scopes\" value=\"platform:deploy-request:create\"> Create Platform deploy requests</label><label><input type=\"checkbox\" name=\"scopes\" value=\"platform:ssh-access:request\"> Request temporary Platform SSH access</label><label><input type=\"checkbox\" name=\"scopes\" value=\"identity:role-request:create\"> Create Identity role requests</label><button type=\"submit\">Create request credential</button></form><table><thead><tr><th>Label</th><th>Scopes</th><th>Created</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead><tbody>{credentials}</tbody></table>\
         <h2>Profiles</h2><table><thead><tr><th>Name</th><th>Steam</th><th>GitHub</th><th>Effective roles</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table>\
         <h2>Recent audit events</h2><table><thead><tr><th>ID</th><th>Unix time</th><th>Event</th><th>Actor</th><th>Subject</th><th>Detail</th></tr></thead><tbody>{audit}</tbody></table></main></body></html>",
        html_escape(current.steam_id64.as_deref().unwrap_or("unknown")),
        github_browser_ready(&state.config)
    ))
}

fn admin_html_response(body: String) -> Response {
    admin_private_response(Html(body).into_response())
}

fn admin_text_response(status: StatusCode, body: &str) -> Response {
    admin_private_response(text_response(status, body))
}

fn admin_redirect_response(location: &str) -> Response {
    admin_private_response(redirect_response(location))
}

fn admin_private_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    response
}

pub(crate) async fn admin_grant_role_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<GrantRoleRequest>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: admin form requires a same-origin browser request",
        );
    }
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) => current,
        Ok(None) => {
            return admin_text_response(
                StatusCode::UNAUTHORIZED,
                "identity: sign in with a root profile before granting roles",
            );
        }
        Err(error) => {
            return admin_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate dashboard session: {error}"),
            );
        }
    };
    if !current.root_authorized {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: root role is required to grant roles",
        );
    }

    let response = create_permission_request(
        State(state),
        headers,
        Json(CreatePermissionRequest {
            action: "grant".to_string(),
            role: request.role,
            steam_id64: request.steam_id64,
            github_login: request.github_login,
        }),
    )
    .await;
    permission_request_form_response(response, "grant").await
}

pub(crate) async fn admin_revoke_role_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<RevokeRoleRequest>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: admin form requires a same-origin browser request",
        );
    }
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) => current,
        Ok(None) => {
            return admin_text_response(
                StatusCode::UNAUTHORIZED,
                "identity: sign in with a root profile before revoking roles",
            );
        }
        Err(error) => {
            return admin_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate dashboard session: {error}"),
            );
        }
    };
    if !current.root_authorized {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: root role is required to revoke roles",
        );
    }

    let response = create_permission_request(
        State(state),
        headers,
        Json(CreatePermissionRequest {
            action: "revoke".to_string(),
            role: request.role,
            steam_id64: request.steam_id64,
            github_login: request.github_login,
        }),
    )
    .await;
    permission_request_form_response(response, "revoke").await
}

async fn permission_request_form_response(response: Response, action: &str) -> Response {
    let status = response.status();
    if status == StatusCode::ACCEPTED {
        let body = match to_bytes(response.into_body(), 4096).await {
            Ok(body) => body,
            Err(_) => {
                return admin_text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "identity: request was recorded but its receipt could not be read",
                )
            }
        };
        let id = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".to_string());
        return admin_redirect_response(&format!(
            "/admin/identity?notice={}",
            percent_encode(&format!("{action} request {id} is pending root approval"))
        ));
    }
    let body = match to_bytes(response.into_body(), 8192).await {
        Ok(body) => String::from_utf8_lossy(&body).trim().to_string(),
        Err(_) => "request failed".to_string(),
    };
    admin_redirect_response(&format!(
        "/admin/identity?error={}",
        percent_encode(&format!("role {action} request failed: {body}"))
    ))
}

pub(crate) async fn admin_approve_permission_request_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(request): Form<ApprovePermissionRequest>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: same-origin request required",
        );
    }
    let response = approve_permission_request(State(state), headers, Path(id), Json(request)).await;
    permission_decision_form_response(response, "approve").await
}

pub(crate) async fn admin_reject_permission_request_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(request): Form<RejectPermissionRequest>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: same-origin request required",
        );
    }
    let response = reject_permission_request(State(state), headers, Path(id), Json(request)).await;
    permission_decision_form_response(response, "reject").await
}

pub(crate) async fn admin_create_automation_credential_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutomationCredentialForm>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: same-origin request required",
        );
    }
    if !(1..=90).contains(&form.expires_in_days) {
        return admin_redirect_response(
            "/admin/identity?error=credential%20expiry%20must%20be%201%20to%2090%20days",
        );
    }
    let request = CreateAutomationCredentialRequest {
        label: form.label,
        expires_at_unix: unix_now_i64() + form.expires_in_days * 24 * 60 * 60,
        scopes: form.scopes,
    };
    let response = create_automation_credential(State(state), headers, Json(request)).await;
    if response.status() != StatusCode::CREATED {
        return permission_decision_form_response(response, "credential creation").await;
    }
    let bytes = match to_bytes(response.into_body(), 8192).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return admin_text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity: credential created, but its one-time response could not be read",
            )
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return admin_text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity: credential created, but its response was invalid",
            )
        }
    };
    let token = value
        .get("bearer_token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let label = value
        .get("label")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("automation");
    admin_private_response(Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Credential created · Vapor Identity</title><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\"><script defer src=\"/admin/assets/admin.js\"></script></head><body><main id=\"admin-content\"><p class=\"eyebrow\">Identity</p><h1>Credential created</h1><p>Copy this request-only secret now. It will not be shown again.</p><p><strong>{}</strong></p><pre><code>{}</code></pre><p><a href=\"/admin/identity\">Return to Identity administration</a></p></main></body></html>",
        html_escape(label), html_escape(token)
    )).into_response())
}

pub(crate) async fn admin_revoke_automation_credential_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !same_origin_browser_request(&headers, &state.config) {
        return admin_text_response(
            StatusCode::FORBIDDEN,
            "identity: same-origin request required",
        );
    }
    match revoke_automation_credential(State(state), headers, Path(id))
        .await
        .status()
    {
        StatusCode::NO_CONTENT => {
            admin_redirect_response("/admin/identity?notice=automation%20credential%20revoked")
        }
        status => admin_redirect_response(&format!(
            "/admin/identity?error={}",
            percent_encode(&format!("credential revoke failed ({status})"))
        )),
    }
}

async fn permission_decision_form_response(response: Response, decision: &str) -> Response {
    if response.status().is_success() {
        return admin_redirect_response(&format!(
            "/admin/identity?notice={}",
            percent_encode(&format!("Permission request {decision}ed"))
        ));
    }
    let status = response.status();
    let body = match to_bytes(response.into_body(), 8192).await {
        Ok(body) => String::from_utf8_lossy(&body).trim().to_string(),
        Err(_) => "request failed".to_string(),
    };
    admin_redirect_response(&format!(
        "/admin/identity?error={}",
        percent_encode(&format!(
            "Permission request {decision} failed ({status}): {body}"
        ))
    ))
}

fn role_action_forms(row: &ProfileRow) -> String {
    let Some(steam_id64) = row
        .steam_ids
        .as_deref()
        .and_then(|value| value.split(',').find(|part| !part.trim().is_empty()))
        .map(str::trim)
    else {
        return "no linked Steam identity".to_string();
    };
    let Some(github_login) = row
        .github_logins
        .as_deref()
        .and_then(|value| value.split(',').find(|part| !part.trim().is_empty()))
        .map(str::trim)
    else {
        return "no linked GitHub identity".to_string();
    };
    if row.stored_roles.is_empty() {
        return "no active stored role".to_string();
    }

    let mut forms = String::new();
    for role in &row.stored_roles {
        forms.push_str(&format!(
            "<form class=\"inline\" method=\"post\" action=\"/admin/identity/roles/revoke\">\
             <input type=\"hidden\" name=\"role\" value=\"{}\">\
             <input type=\"hidden\" name=\"steam_id64\" value=\"{}\">\
             <input type=\"hidden\" name=\"github_login\" value=\"{}\">\
             <button type=\"submit\">Revoke {}</button></form>",
            html_escape(role),
            html_escape(steam_id64),
            html_escape(github_login),
            html_escape(role),
        ));
    }
    forms
}

fn external_identity_label(steam_ids: Option<&str>, github_logins: Option<&str>) -> String {
    let steam = steam_ids.unwrap_or("").trim();
    let github = github_logins.unwrap_or("").trim();
    match (steam.is_empty(), github.is_empty()) {
        (true, true) => "server-local".to_string(),
        (false, true) => format!("Steam {steam}"),
        (true, false) => format!("GitHub {github}"),
        (false, false) => format!("Steam {steam} / GitHub {github}"),
    }
}
