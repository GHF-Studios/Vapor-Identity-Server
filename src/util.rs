use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::config::{AuthConfig, DASHBOARD_SESSION_TTL_SECONDS, SESSION_COOKIE};
use crate::profiles::CurrentProfile;

pub(crate) fn authorized(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {expected}"))
}

pub(crate) fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(token.to_string());
    }

    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    cookie_header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            if name == SESSION_COOKIE && !value.is_empty() {
                Some(value.to_string())
            } else {
                None
            }
        })
}

pub(crate) fn session_cookie(config: &AuthConfig, token: &str, max_age_seconds: i64) -> String {
    let secure = if config.cookie_secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; Path={}; Max-Age={max_age_seconds}; HttpOnly; SameSite=Lax{secure}",
        config.cookie_path
    )
}

pub(crate) fn expired_session_cookie(config: &AuthConfig) -> String {
    let secure = if config.cookie_secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}=; Path={}; Max-Age=0; HttpOnly; SameSite=Lax{secure}",
        config.cookie_path
    )
}

pub(crate) fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn dashboard_identity_ready(config: &AuthConfig) -> bool {
    github_browser_ready(config)
}

pub(crate) fn github_browser_ready(config: &AuthConfig) -> bool {
    config.github_client_id.is_some() && config.github_client_secret.is_some()
}

pub(crate) fn github_device_ready(config: &AuthConfig) -> bool {
    config.github_client_id.is_some()
}

pub(crate) fn login_html(config: &AuthConfig, current: Option<&CurrentProfile>) -> String {
    let body = if let Some(profile) = current {
        let roles = display_roles(profile);
        let github = profile.github_login.as_deref().unwrap_or("not linked");
        let github_action = if profile.github_login.is_some() {
            "<p>GitHub identity is linked.</p>".to_string()
        } else if github_browser_ready(config) {
            "<p><a href=\"/login/github\">Link GitHub account</a></p>".to_string()
        } else {
            "<p>GitHub browser login is not configured yet. Steam/player login still works.</p>"
                .to_string()
        };
        format!(
            "<p>Signed in as Steam profile <code>{}</code>.</p>\
             <dl><dt>Display name</dt><dd>{}</dd>\
             <dt>SteamID64</dt><dd>{}</dd>\
             <dt>GitHub</dt><dd>{}</dd>\
             <dt>Roles</dt><dd>{}</dd></dl>\
             {github_action}\
             <p><a href=\"/admin\">Open admin dashboard</a> · <a href=\"/logout\">Logout</a></p>",
            html_escape(&profile.profile_id),
            html_escape(profile.display_name.as_deref().unwrap_or("")),
            html_escape(profile.steam_id64.as_deref().unwrap_or("")),
            html_escape(github),
            html_escape(&roles),
        )
    } else {
        "<p>Vapor profiles are anchored by Steam identity. No Vapor username or password is required.</p>\
         <p><a href=\"/login/steam\">Sign in / register with Steam</a></p>\
         <p>GitHub is linked after Steam login when development or root access is needed.</p>"
            .to_string()
    };

    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Login</title>\
         <style>body{{max-width:840px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}dt{{font-weight:700}}dd{{margin:0 0 .5rem 0}}</style>\
         <h1>Vapor Login</h1>{body}\
         <h2>Readiness</h2>\
         <ul><li>Steam browser login: <code>true</code></li>\
         <li>GitHub browser login configured: <code>{}</code></li>\
         <li>GitHub Device Flow configured: <code>{}</code></li>\
         <li>Session TTL: <code>{DASHBOARD_SESSION_TTL_SECONDS}s</code></li></ul>\
         <p><a href=\"/\">Home</a></p>",
        github_browser_ready(config),
        config.github_client_id.is_some()
    )
}

pub(crate) fn admin_locked_html(current: Option<&CurrentProfile>) -> String {
    let body = if let Some(profile) = current {
        format!(
            "<p>You are signed in as Steam profile <code>{}</code>, but this profile is not authorized for root/admin access.</p>\
             <dl><dt>SteamID64</dt><dd>{}</dd><dt>GitHub</dt><dd>{}</dd><dt>Roles</dt><dd>{}</dd></dl>\
             <p><a href=\"/login\">Manage identity</a> · <a href=\"/logout\">Logout</a></p>",
            html_escape(&profile.profile_id),
            html_escape(profile.steam_id64.as_deref().unwrap_or("")),
            html_escape(profile.github_login.as_deref().unwrap_or("not linked")),
            html_escape(&display_roles(profile)),
        )
    } else {
        "<p>The admin dashboard is publicly reachable, but locked. Sign in to check whether your Steam profile has admin access.</p>\
         <p><a href=\"/login\">Login / register</a></p>"
            .to_string()
    };

    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Vapor Identity Admin</title>\
         <style>body{{max-width:840px;margin:3rem auto;padding:0 1.5rem;font:16px/1.5 system-ui,sans-serif}}\
         code{{background:#f4f4f4;padding:.1rem .25rem;border-radius:.2rem}}dt{{font-weight:700}}dd{{margin:0 0 .5rem 0}}</style>\
         <h1>Vapor Identity Admin</h1>{body}\
         <p>Admin access requires linked Steam and GitHub identities plus the <code>root</code> role.</p>"
    )
}

pub(crate) fn display_roles(profile: &CurrentProfile) -> String {
    let mut roles = vec!["player".to_string()];
    roles.extend(profile.roles.iter().cloned());
    roles.sort();
    roles.dedup();
    roles.join(", ")
}

pub(crate) fn redirect_response(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, location.to_string())],
        "",
    )
        .into_response()
}

pub(crate) fn redirect_with_cookie(config: &AuthConfig, location: &str, token: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (
                SET_COOKIE,
                session_cookie(config, token, DASHBOARD_SESSION_TTL_SECONDS),
            ),
            (LOCATION, location.to_string()),
        ],
        "",
    )
        .into_response()
}

pub(crate) fn public_origin(config: &AuthConfig, headers: &HeaderMap) -> String {
    if let Some(origin) = config.public_origin.as_deref() {
        return origin.to_string();
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_public_host(value))
        .unwrap_or("127.0.0.1:7113");
    format!("{proto}://{host}")
}

pub(crate) fn valid_public_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains(';')
        && !value.contains('\r')
        && !value.contains('\n')
}

pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

pub(crate) fn steam_id_from_openid_claim(value: &str) -> Option<String> {
    let steam_id = value
        .strip_prefix("https://steamcommunity.com/openid/id/")
        .or_else(|| value.strip_prefix("http://steamcommunity.com/openid/id/"))?;
    if steam_id.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(steam_id.to_string())
    } else {
        None
    }
}

pub(crate) fn first_csv(value: Option<&str>) -> Option<String> {
    value
        .and_then(|value| value.split(',').find(|part| !part.trim().is_empty()))
        .map(|value| value.trim().to_string())
}

pub(crate) fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                None
            } else {
                Some(part.to_string())
            }
        })
        .collect()
}

pub(crate) fn valid_profile_id(value: &str) -> bool {
    value.starts_with("profile-")
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(crate) fn valid_auth_attempt_id(value: &str) -> bool {
    value.starts_with("auth-")
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(crate) fn valid_browser_state(value: &str) -> bool {
    value.starts_with("login-")
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(crate) fn valid_hex_ticket(ticket: &str) -> bool {
    !ticket.is_empty()
        && ticket.len() <= 8192
        && ticket.len().is_multiple_of(2)
        && ticket.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn steam_id_from_response(value: &Value) -> Option<String> {
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

pub(crate) fn new_profile_id() -> String {
    format!("profile-{}", Uuid::new_v4())
}

pub(crate) fn new_auth_attempt_id() -> String {
    format!("auth-{}", Uuid::new_v4())
}

pub(crate) fn new_browser_login_state() -> String {
    format!("login-{}-{}", Uuid::new_v4(), Uuid::new_v4())
}

pub(crate) fn new_session_id() -> String {
    format!("session-{}", Uuid::new_v4())
}

pub(crate) fn new_session_token() -> String {
    format!("vapor-session-{}-{}", Uuid::new_v4(), Uuid::new_v4())
}

pub(crate) fn text_response(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

pub(crate) fn unix_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(crate) fn toml_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("\"{escaped}\"")
}

pub(crate) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
