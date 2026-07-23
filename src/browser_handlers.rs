use axum::extract::{Query, State};
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use std::collections::HashMap;

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
         <p>Signed in as Steam profile <code>{}</code>. Root role is active.</p>\
         <p><a href=\"/login\">Identity</a> · <a href=\"/logout\">Logout</a></p>\
         <h2>Readiness</h2>\
         <ul><li>Steam browser login: <code>true</code></li>\
         <li>GitHub browser login configured: <code>{}</code></li>\
         <li>Dashboard session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <h2>Profiles</h2><table><thead><tr><th>Profile</th><th>Name</th><th>Steam</th><th>GitHub</th><th>Roles</th></tr></thead><tbody>{rows}</tbody></table>",
        html_escape(&current.profile_id),
        github_browser_ready(&state.config)
    ))
    .into_response()
}
