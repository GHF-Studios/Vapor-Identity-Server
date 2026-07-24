use axum::extract::{Query, State};
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use std::collections::HashMap;

use crate::admin_handlers::{grant_role_request, revoke_role_request};
use crate::config::{
    BROWSER_LOGIN_ATTEMPT_TTL_SECONDS, DASHBOARD_SESSION_TTL_SECONDS, STEAM_OPENID_ENDPOINT,
};
use crate::persistence::*;
use crate::providers::{exchange_github_web_code, verify_github_access_token, verify_steam_openid};
use crate::types::*;
use crate::util::{
    admin_locked_html, expired_session_cookie, github_browser_ready, html_escape, login_html,
    new_browser_login_state, percent_encode, public_origin, redirect_response,
    redirect_with_cookie, session_token_from_headers, text_response, unix_now_i64,
    valid_browser_state,
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
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to validate dashboard session: {error}\n"),
            )
                .into_response();
        }
    };
    let Some(current) = current else {
        return Html(admin_locked_html(None)).into_response();
    };
    if !current.root_authorized {
        return Html(admin_locked_html(Some(&current))).into_response();
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
    let audit_rows = match recent_audit_events(&state.pool, 25).await {
        Ok(rows) => rows,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to load dashboard audit events: {error}\n"),
            )
                .into_response();
        }
    };
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

    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Identity Admin</title>\
         <style>body{{max-width:1100px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem;text-align:left}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}\
         label{{display:block;margin:.6rem 0}}input,select{{font:inherit;padding:.3rem;min-width:20rem}}\
         button{{font:inherit;padding:.4rem .7rem}}form.inline{{display:inline}}form.inline button{{padding:.2rem .45rem;margin:.1rem}}\
         .notice{{background:#e7f6e7;padding:.6rem;border-left:4px solid #2d7a2d}}\
         .error{{background:#fdeaea;padding:.6rem;border-left:4px solid #b42318}}</style>\
         <h1>Vapor Identity Admin</h1>\
         <p>Signed in as Steam profile <code>{}</code>. Root role is active.</p>\
         <p><a href=\"/login\">Identity</a> · <a href=\"/logout\">Logout</a></p>\
         {notice}{error}\
         <h2>Readiness</h2>\
         <ul><li>Steam browser login: <code>true</code></li>\
         <li>GitHub browser login configured: <code>{}</code></li>\
         <li>Dashboard session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <h2>Grant role</h2>\
         <form method=\"post\" action=\"/admin/roles/grant\">\
         <label>Role <select name=\"role\"><option value=\"content-developer\">content-developer</option><option value=\"root\">root</option></select></label>\
         <label>SteamID64 <input name=\"steam_id64\" inputmode=\"numeric\" pattern=\"[0-9]{{17}}\" required></label>\
         <label>GitHub login <input name=\"github_login\" required></label>\
         <button type=\"submit\">Grant role</button></form>\
         <p>This form requires your root dashboard session. It still refuses grants unless the SteamID64 and GitHub login are already linked to the same profile.</p>\
         <p>Root implies content-developer. To demote a root profile to developer, first grant <code>content-developer</code>, then revoke <code>root</code>.</p>\
         <h2>Profiles</h2><table><thead><tr><th>Name</th><th>Steam</th><th>GitHub</th><th>Effective roles</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table>\
         <h2>Recent audit events</h2><table><thead><tr><th>ID</th><th>Unix time</th><th>Event</th><th>Actor</th><th>Subject</th><th>Detail</th></tr></thead><tbody>{audit}</tbody></table>",
        html_escape(current.steam_id64.as_deref().unwrap_or("unknown")),
        github_browser_ready(&state.config)
    ))
    .into_response()
}

pub(crate) async fn admin_grant_role_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<GrantRoleRequest>,
) -> Response {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) => current,
        Ok(None) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: sign in with a root profile before granting roles",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate dashboard session: {error}"),
            );
        }
    };
    if !current.root_authorized {
        return text_response(
            StatusCode::FORBIDDEN,
            "identity: root role is required to grant roles",
        );
    }

    match grant_role_request(&state, &request, Some(&current.profile_id)).await {
        Ok(response) => {
            let action = if response.granted {
                "granted"
            } else {
                "already active"
            };
            redirect_response(&format!(
                "/admin?notice={}",
                percent_encode(&format!(
                    "{} {} for SteamID64 {} / GitHub {}",
                    action, response.role, response.steam_id64, response.github_login
                ))
            ))
        }
        Err(error) => redirect_response(&format!(
            "/admin?error={}",
            percent_encode(&format!("role grant failed: {}", error.message))
        )),
    }
}

pub(crate) async fn admin_revoke_role_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<RevokeRoleRequest>,
) -> Response {
    let current = match current_profile_from_headers(&state.pool, &headers).await {
        Ok(Some(current)) => current,
        Ok(None) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: sign in with a root profile before revoking roles",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate dashboard session: {error}"),
            );
        }
    };
    if !current.root_authorized {
        return text_response(
            StatusCode::FORBIDDEN,
            "identity: root role is required to revoke roles",
        );
    }

    match revoke_role_request(&state, &request, Some(&current.profile_id)).await {
        Ok(response) => {
            let action = if response.revoked {
                "revoked"
            } else {
                "was not active"
            };
            redirect_response(&format!(
                "/admin?notice={}",
                percent_encode(&format!(
                    "{} {} for SteamID64 {} / GitHub {}",
                    action, response.role, response.steam_id64, response.github_login
                ))
            ))
        }
        Err(error) => redirect_response(&format!(
            "/admin?error={}",
            percent_encode(&format!("role revoke failed: {}", error.message))
        )),
    }
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
            "<form class=\"inline\" method=\"post\" action=\"/admin/roles/revoke\">\
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
