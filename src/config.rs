use std::env;

pub(crate) const DEFAULT_BIND: &str = "127.0.0.1:7113";
pub(crate) const DEFAULT_STATE_DIR: &str = "state/identity";
pub(crate) const DEFAULT_DB_NAME: &str = "identity.sqlite3";
pub(crate) const DEFAULT_STEAM_APP_ID: u32 = 2_122_620;
pub(crate) const DEFAULT_STEAM_AUTH_IDENTITY: &str = "vapor-identity";
pub(crate) const MAX_AUTH_BODY_BYTES: usize = 16 * 1024;
pub(crate) const AUTH_ATTEMPT_TTL_SECONDS: i64 = 5 * 60;
pub(crate) const BROWSER_LOGIN_ATTEMPT_TTL_SECONDS: i64 = 10 * 60;
pub(crate) const DASHBOARD_SESSION_TTL_SECONDS: i64 = 5 * 60;
pub(crate) const SESSION_COOKIE: &str = "vapor_identity_session";
pub(crate) const STEAM_OPENID_ENDPOINT: &str = "https://steamcommunity.com/openid/login";

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) steam_app_id: u32,
    pub(crate) steam_auth_identity: String,
    pub(crate) steam_web_api_key: Option<String>,
    pub(crate) github_client_id: Option<String>,
    pub(crate) github_client_secret: Option<String>,
    pub(crate) dashboard_password: Option<String>,
    pub(crate) cookie_secure: bool,
    pub(crate) cookie_path: String,
    pub(crate) public_origin: Option<String>,
}

pub(crate) fn read_auth_config() -> AuthConfig {
    AuthConfig {
        steam_app_id: env::var("VAPOR_IDENTITY_STEAM_APP_ID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(DEFAULT_STEAM_APP_ID),
        steam_auth_identity: env::var("VAPOR_IDENTITY_STEAM_AUTH_IDENTITY")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_STEAM_AUTH_IDENTITY.to_string()),
        steam_web_api_key: env::var("VAPOR_IDENTITY_STEAM_WEB_API_KEY")
            .ok()
            .filter(|value| !value.is_empty()),
        github_client_id: env::var("VAPOR_IDENTITY_GITHUB_CLIENT_ID")
            .ok()
            .filter(|value| !value.is_empty()),
        github_client_secret: env::var("VAPOR_IDENTITY_GITHUB_CLIENT_SECRET")
            .ok()
            .filter(|value| !value.is_empty()),
        dashboard_password: env::var("VAPOR_IDENTITY_DASHBOARD_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty()),
        cookie_secure: env::var("VAPOR_IDENTITY_COOKIE_SECURE")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on")),
        cookie_path: env::var("VAPOR_IDENTITY_COOKIE_PATH")
            .ok()
            .filter(|value| {
                value.starts_with('/')
                    && !value.contains(';')
                    && !value.contains('\r')
                    && !value.contains('\n')
            })
            .unwrap_or_else(|| "/".to_string()),
        public_origin: env::var("VAPOR_IDENTITY_PUBLIC_ORIGIN")
            .ok()
            .filter(|value| valid_public_origin(value)),
    }
}

fn valid_public_origin(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.ends_with('/')
        && !value.contains(';')
        && !value.contains('\r')
        && !value.contains('\n')
}
