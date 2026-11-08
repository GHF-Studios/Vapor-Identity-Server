use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, COOKIE, LOCATION, SET_COOKIE};
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

pub(crate) fn authorization_service_authorized(
    headers: &HeaderMap,
    expected: Option<&str>,
) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(provided) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_equal(expected.as_bytes(), provided.as_bytes())
}

fn constant_time_equal(expected: &[u8], provided: &[u8]) -> bool {
    let mut difference = expected.len() ^ provided.len();
    for index in 0..expected.len().max(provided.len()) {
        let left = expected.get(index).copied().unwrap_or(0);
        let right = provided.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
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

pub(crate) fn same_origin_browser_request(headers: &HeaderMap, config: &AuthConfig) -> bool {
    let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) else {
        return false;
    };
    config
        .public_origin
        .as_deref()
        .is_some_and(|expected| origin == expected)
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
        let display_name = profile
            .display_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("Steam account");
        let (access_summary, destination, destination_label) = if profile.root_authorized {
            (
                "This account can access the Platform operator dashboard.",
                "/admin",
                "Open Platform admin",
            )
        } else {
            (
                "This account does not have Platform operator access.",
                "/",
                "Return to Vapor",
            )
        };
        let github = profile.github_login.as_deref();
        let github_action = if profile.github_login.is_some() {
            format!(
                "<p class=\"account-note\">GitHub is linked as <strong>{}</strong>. Linking GitHub does not grant operator access.</p>",
                html_escape(github.unwrap_or_default())
            )
        } else if github_browser_ready(config) {
            "<p class=\"account-note\">GitHub is optional. Link it when a creator workflow requires it; linking alone does not grant operator access.</p><p><a class=\"secondary-action\" href=\"/login/github\">Link GitHub</a></p>".to_string()
        } else {
            "<p class=\"account-note\">GitHub linking is currently unavailable. Steam sign-in still works.</p>".to_string()
        };
        format!(
            "<p class=\"signed-in\">Signed in as <strong>{}</strong> with Steam.</p>\
             <p class=\"account-note\">{}</p>\
             <p class=\"actions\"><a class=\"primary-action\" href=\"{}\">{}</a><a class=\"secondary-action\" href=\"/logout\">Sign out</a></p>\
             {}",
            html_escape(display_name),
            access_summary,
            destination,
            destination_label,
            github_action,
        )
    } else {
        "<p class=\"lead\">Use Steam to sign in to your Vapor account.</p>\
         <p class=\"account-note\">Signing in is only needed for account features. Downloading Vapor and browsing public content do not require an account.</p>\
         <p class=\"actions\"><a class=\"primary-action\" href=\"/login/steam\">Continue with Steam</a><a class=\"secondary-action\" href=\"/\">Back to Vapor</a></p>\
         <p class=\"account-note\">GitHub is optional. Link it after sign-in when a creator workflow asks for it; it does not grant administrator access.</p>"
            .to_string()
    };

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"theme-color\" content=\"#10161d\"><title>Sign in · Vapor</title>\
         <style>:root{{color-scheme:dark;font:16px/1.55 Inter,ui-sans-serif,system-ui,sans-serif;background:#10161d;color:#eef3f7;font-synthesis:none}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% -24%,#294346 0,#10161d 58%)}}a{{color:#a9d8cb}}a:focus-visible{{outline:2px solid #9fe1ce;outline-offset:4px;border-radius:3px}}main{{width:min(680px,calc(100% - 36px));margin:0 auto;padding:28px 0 56px}}nav{{display:flex;align-items:center;gap:20px;padding-bottom:clamp(58px,12vh,112px)}}.brand{{margin-right:auto;color:#eef3f7;font-weight:780;letter-spacing:.04em;text-decoration:none}}nav a:not(.brand){{color:#bac7ce;text-decoration:none;font-size:.92rem}}.eyebrow{{color:#9fe1ce;font-size:.76rem;font-weight:750;letter-spacing:.16em;text-transform:uppercase}}h1{{margin:10px 0 16px;font-size:clamp(2.5rem,7vw,4rem);letter-spacing:-.06em;line-height:1}}.panel{{padding:clamp(22px,5vw,36px);border:1px solid #34434a;border-radius:12px;background:rgba(20,29,35,.94);box-shadow:0 22px 80px rgba(0,0,0,.2)}}.lead{{margin:0;color:#c3cfd4;font-size:1.1rem}}.account-note{{margin:14px 0 0;color:#aebdc3;font-size:.92rem;line-height:1.65}}.signed-in{{margin:0;color:#c3cfd4}}.actions{{display:flex;align-items:center;flex-wrap:wrap;gap:16px;margin:22px 0 0}}.primary-action{{display:inline-flex;min-height:44px;align-items:center;justify-content:center;padding:0 17px;border-radius:7px;background:#9fe1ce;color:#10201d;font-weight:760;text-decoration:none}}.primary-action:hover{{background:#b8f0df}}.secondary-action{{font-weight:650;text-decoration:none}}footer{{margin-top:24px;color:#7f9298;font-size:.82rem}}@media(max-width:520px){{nav{{padding-bottom:54px}}.actions{{align-items:flex-start;flex-direction:column;gap:14px}}}}</style></head><body><main><nav aria-label=\"Main navigation\"><a class=\"brand\" href=\"/\">VAPOR</a><a href=\"/docs/\">Documentation</a></nav><section class=\"panel\" aria-labelledby=\"login-title\"><p class=\"eyebrow\">Vapor account</p><h1 id=\"login-title\">{}</h1>{body}</section><footer>Vapor sign-in uses Steam. Your game files remain local to you.</footer></main></body></html>",
        if current.is_some() { "Your account" } else { "Sign in to Vapor" }
    )
}

pub(crate) fn admin_locked_html(current: Option<&CurrentProfile>) -> String {
    let body = if let Some(profile) = current {
        format!(
            "<p>You are signed in as Steam profile <code>{}</code>, but this profile is not authorized for root/admin access.</p>\
             <dl><dt>SteamID64</dt><dd>{}</dd><dt>GitHub</dt><dd>{}</dd><dt>Roles</dt><dd>{}</dd></dl>\
             <p><a href=\"/login\">Manage identity</a> · <a href=\"/logout\">Logout</a></p>",
            html_escape(profile.steam_id64.as_deref().unwrap_or("unknown")),
            html_escape(profile.steam_id64.as_deref().unwrap_or("")),
            html_escape(profile.github_login.as_deref().unwrap_or("not linked")),
            html_escape(&display_roles(profile)),
        )
    } else {
        "<p>Identity administration is locked. Sign in to check whether your Steam profile has admin access.</p>\
         <p><a href=\"/login\">Login / register</a></p>"
            .to_string()
    };

    format!(
        "<p class=\"eyebrow\">Identity</p><h1>Accounts and access</h1>{body}\
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
    let mut response = (
        StatusCode::SEE_OTHER,
        [(LOCATION, location.to_string())],
        "",
    )
        .into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(crate) fn redirect_with_cookie(config: &AuthConfig, location: &str, token: &str) -> Response {
    let mut response = redirect_response(location);
    if let Ok(value) = axum::http::HeaderValue::from_str(&session_cookie(
        config,
        token,
        DASHBOARD_SESSION_TTL_SECONDS,
    )) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

pub(crate) fn browser_login_state_matches(
    headers: &HeaderMap,
    flow: &str,
    expected_state: &str,
) -> bool {
    let Some((cookie_name, _)) = browser_login_cookie(flow) else {
        return false;
    };
    let mut state_cookie_value = None;
    for cookie_header in headers.get_all(COOKIE).iter() {
        let Ok(cookie_header) = cookie_header.to_str() else {
            return false;
        };
        for part in cookie_header.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == cookie_name {
                if state_cookie_value.is_some() {
                    return false;
                }
                state_cookie_value = Some(value);
            }
        }
    }
    state_cookie_value == Some(expected_state)
}

pub(crate) fn redirect_with_login_state_cookie(
    config: &AuthConfig,
    location: &str,
    flow: &str,
    state: &str,
) -> Response {
    let Some((cookie_name, callback_path)) = browser_login_cookie(flow) else {
        return redirect_response(location);
    };
    let secure = if config.cookie_secure { "; Secure" } else { "" };
    let cookie = format!(
        "{cookie_name}={state}; Path={callback_path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}",
        crate::config::BROWSER_LOGIN_ATTEMPT_TTL_SECONDS
    );
    let mut response = redirect_response(location);
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

pub(crate) fn redirect_with_cookie_and_clear_login_state(
    config: &AuthConfig,
    location: &str,
    token: &str,
    flow: &str,
) -> Response {
    let mut response = redirect_with_cookie(config, location, token);
    append_clear_login_state_cookie(&mut response, config, flow);
    response
}

pub(crate) fn redirect_with_clear_login_state(
    config: &AuthConfig,
    location: &str,
    flow: &str,
) -> Response {
    let mut response = redirect_response(location);
    append_clear_login_state_cookie(&mut response, config, flow);
    response
}

fn append_clear_login_state_cookie(response: &mut Response, config: &AuthConfig, flow: &str) {
    if let Some((cookie_name, callback_path)) = browser_login_cookie(flow) {
        let secure = if config.cookie_secure { "; Secure" } else { "" };
        let cookie = format!(
            "{cookie_name}=; Path={callback_path}; Max-Age=0; HttpOnly; SameSite=Lax{secure}"
        );
        if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }
}

fn browser_login_cookie(flow: &str) -> Option<(&'static str, &'static str)> {
    match flow {
        "steam" => Some(("vapor_identity_steam_login_state", "/login/steam/callback")),
        "github" => Some((
            "vapor_identity_github_login_state",
            "/login/github/callback",
        )),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::{
        browser_login_state_matches, redirect_with_cookie, redirect_with_login_state_cookie,
        same_origin_browser_request,
    };
    use crate::config::AuthConfig;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    fn config() -> AuthConfig {
        AuthConfig {
            steam_app_id: 1,
            steam_auth_identity: String::new(),
            steam_web_api_key: None,
            loocast_app_id: 1,
            authorization_service_token: None,
            platform_admin_authorization_service_token: None,
            artifact_admin_authorization_service_token: None,
            build_cache_admin_authorization_service_token: None,
            github_client_id: None,
            github_client_secret: None,
            dashboard_password: None,
            cookie_secure: true,
            cookie_path: "/".to_owned(),
            public_origin: Some("https://vapor.example".to_owned()),
        }
    }

    #[test]
    fn admin_form_requires_exact_configured_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://vapor.example"));
        assert!(same_origin_browser_request(&headers, &config()));

        headers.insert(
            "origin",
            HeaderValue::from_static("https://attacker.example"),
        );
        assert!(!same_origin_browser_request(&headers, &config()));

        headers.remove("origin");
        assert!(!same_origin_browser_request(&headers, &config()));
    }

    #[test]
    fn admin_form_fails_closed_without_configured_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://vapor.example"));
        headers.insert("host", HeaderValue::from_static("vapor.example"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("vapor.example"),
        );
        let mut config = config();
        config.public_origin = None;
        assert!(!same_origin_browser_request(&headers, &config));
    }

    #[test]
    fn browser_login_state_must_match_the_flow_specific_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("vapor_identity_steam_login_state=login-state-1; other=value"),
        );

        assert!(browser_login_state_matches(
            &headers,
            "steam",
            "login-state-1"
        ));
        assert!(!browser_login_state_matches(
            &headers,
            "steam",
            "login-state-2"
        ));
        assert!(!browser_login_state_matches(
            &headers,
            "github",
            "login-state-1"
        ));
        assert!(!browser_login_state_matches(
            &HeaderMap::new(),
            "steam",
            "login-state-1"
        ));
    }

    #[test]
    fn duplicate_browser_state_cookies_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "cookie",
            HeaderValue::from_static("vapor_identity_steam_login_state=login-state-1"),
        );
        headers.append(
            "cookie",
            HeaderValue::from_static("vapor_identity_steam_login_state=login-state-2"),
        );

        assert!(!browser_login_state_matches(
            &headers,
            "steam",
            "login-state-1"
        ));
    }

    #[test]
    fn browser_login_redirect_sets_a_private_flow_scoped_cookie() {
        let response = redirect_with_login_state_cookie(
            &config(),
            "https://steamcommunity.com/openid/login?state=login-state-1",
            "steam",
            "login-state-1",
        );

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .unwrap();
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.contains("Path=/login/steam/callback"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn session_redirect_sets_a_private_no_store_cookie() {
        let response = redirect_with_cookie(&config(), "/login", "session-token");

        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("vapor_identity_session=session-token;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }
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

pub(crate) fn valid_steam_id64(value: &str) -> bool {
    value.len() == 17 && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn valid_github_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
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
