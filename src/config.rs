use std::env;

pub(crate) const DEFAULT_BIND: &str = "127.0.0.1:7113";
pub(crate) const DEFAULT_STATE_DIR: &str = "state/identity";
pub(crate) const DEFAULT_DB_NAME: &str = "identity.sqlite3";
pub(crate) const DEFAULT_STEAM_APP_ID: u32 = 2_122_620;
pub(crate) const DEFAULT_LOOCAST_APP_ID: u32 = 2_122_620;
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
    pub(crate) loocast_app_id: u32,
    pub(crate) authorization_service_token: Option<String>,
    pub(crate) platform_admin_authorization_service_token: Option<String>,
    pub(crate) artifact_admin_authorization_service_token: Option<String>,
    pub(crate) build_cache_admin_authorization_service_token: Option<String>,
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
        loocast_app_id: env::var("VAPOR_IDENTITY_LOOCAST_APP_ID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != 0)
            .unwrap_or(DEFAULT_LOOCAST_APP_ID),
        authorization_service_token: env::var("VAPOR_IDENTITY_AUTHZ_SERVICE_TOKEN")
            .ok()
            .filter(|value| valid_service_token(value)),
        platform_admin_authorization_service_token: env::var(
            "VAPOR_IDENTITY_PLATFORM_ADMIN_AUTHZ_TOKEN",
        )
        .ok()
        .filter(|value| valid_service_token(value)),
        artifact_admin_authorization_service_token: env::var(
            "VAPOR_IDENTITY_ARTIFACT_ADMIN_AUTHZ_TOKEN",
        )
        .ok()
        .filter(|value| valid_service_token(value)),
        build_cache_admin_authorization_service_token: env::var(
            "VAPOR_IDENTITY_BUILD_CACHE_ADMIN_AUTHZ_TOKEN",
        )
        .ok()
        .filter(|value| valid_service_token(value)),
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

fn valid_service_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_public_origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.as_str().strip_suffix('/') == Some(value)
}

#[cfg(test)]
mod tests {
    use super::valid_public_origin;

    #[test]
    fn public_origin_accepts_only_canonical_bare_http_origins() {
        assert!(valid_public_origin("https://vapor.example"));
        assert!(valid_public_origin("http://localhost:7113"));
        assert!(!valid_public_origin("https://vapor.example/"));
        assert!(!valid_public_origin("https://vapor.example/admin"));
        assert!(!valid_public_origin("https://vapor.example?next=/admin"));
        assert!(!valid_public_origin("https://vapor.example#fragment"));
        assert!(!valid_public_origin("https://user@vapor.example"));
        assert!(!valid_public_origin("file://vapor.example"));
    }
}
