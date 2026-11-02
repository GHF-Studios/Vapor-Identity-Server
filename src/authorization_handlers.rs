use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::persistence::{
    cache_steam_entitlement, cached_steam_entitlement, profile_from_session_token,
};
use crate::providers::check_steam_app_ownership;
use crate::types::AppState;
use crate::util::{authorization_service_authorized, unix_now_i64};

const ENTITLEMENT_CACHE_TTL_SECONDS: i64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizationCheckRequest {
    audience: String,
    session_token: String,
    policy: AuthorizationPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationPolicy {
    mode: PolicyMode,
    requirements: Vec<AuthorizationRequirement>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyMode {
    All,
    Any,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AuthorizationRequirement {
    ProductEntitlement {
        product_id: String,
        license_mode: LicenseMode,
    },
    Role {
        role: String,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LicenseMode {
    Active,
    Permanent,
}

#[derive(Serialize)]
struct AuthorizationCheckResponse {
    allowed: bool,
    expires_at_unix: i64,
}

pub(crate) async fn check_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthorizationCheckRequest>,
) -> Response {
    if !matches!(
        request.audience.as_str(),
        "vapor-registry"
            | "vapor-platform-admin"
            | "vapor-artifact-admin"
            | "vapor-build-cache-admin"
    ) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let expected_service_token = service_token_for_audience(&state.config, &request.audience);
    if !authorization_service_authorized(&headers, expected_service_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if request.policy.requirements.is_empty()
        || request.policy.requirements.len() > 16
        || request.session_token.len() < 32
        || request.session_token.len() > 256
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let profile = match profile_from_session_token(&state.pool, &request.session_token).await {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return authorization_response(false, unix_now_i64());
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut any_allowed = false;
    let mut all_allowed = true;
    let mut earliest_expiry = unix_now_i64() + ENTITLEMENT_CACHE_TTL_SECONDS;
    for requirement in &request.policy.requirements {
        let allowed = match requirement {
            AuthorizationRequirement::Role { role } => {
                matches!(role.as_str(), "root" | "content-developer")
                    && profile.roles.iter().any(|candidate| candidate == role)
            }
            AuthorizationRequirement::ProductEntitlement {
                product_id,
                license_mode,
            } => {
                let Some(steam_id64) = profile.steam_id64.as_deref() else {
                    all_allowed = false;
                    continue;
                };
                if product_id != "loo-cast" {
                    all_allowed = false;
                    continue;
                }
                let entitlement = match product_entitlement(&state, steam_id64).await {
                    Ok((ownership, expires_at)) => {
                        earliest_expiry = earliest_expiry.min(expires_at);
                        match license_mode {
                            LicenseMode::Active => ownership.active,
                            LicenseMode::Permanent => ownership.permanent,
                        }
                    }
                    Err(()) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
                };
                entitlement
            }
        };
        any_allowed |= allowed;
        all_allowed &= allowed;
    }

    let allowed = match request.policy.mode {
        PolicyMode::All => all_allowed,
        PolicyMode::Any => any_allowed,
    };
    authorization_response(allowed, earliest_expiry)
}

fn service_token_for_audience<'a>(
    config: &'a crate::config::AuthConfig,
    audience: &str,
) -> Option<&'a str> {
    match audience {
        "vapor-registry" => config.authorization_service_token.as_deref(),
        "vapor-platform-admin" => config.platform_admin_authorization_service_token.as_deref(),
        "vapor-artifact-admin" => config.artifact_admin_authorization_service_token.as_deref(),
        "vapor-build-cache-admin" => config
            .build_cache_admin_authorization_service_token
            .as_deref(),
        _ => None,
    }
}

async fn product_entitlement(
    state: &AppState,
    steam_id64: &str,
) -> Result<(crate::providers::SteamAppOwnership, i64), ()> {
    let now = unix_now_i64();
    if let Some(cached) = cached_steam_entitlement(&state.pool, steam_id64, "loo-cast", now)
        .await
        .map_err(|_| ())?
    {
        return Ok(cached);
    }

    let key = state.config.steam_web_api_key.as_deref().ok_or(())?;
    let ownership =
        check_steam_app_ownership(&state.http, key, steam_id64, state.config.loocast_app_id)
            .await?;
    let expires_at = now + ENTITLEMENT_CACHE_TTL_SECONDS;
    cache_steam_entitlement(
        &state.pool,
        steam_id64,
        "loo-cast",
        ownership,
        now,
        expires_at,
    )
    .await
    .map_err(|_| ())?;
    Ok((ownership, expires_at))
}

fn authorization_response(allowed: bool, expires_at_unix: i64) -> Response {
    (
        StatusCode::OK,
        [("cache-control", "no-store")],
        Json(AuthorizationCheckResponse {
            allowed,
            expires_at_unix,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::service_token_for_audience;
    use crate::config::AuthConfig;

    fn config() -> AuthConfig {
        AuthConfig {
            steam_app_id: 1,
            steam_auth_identity: String::new(),
            steam_web_api_key: None,
            loocast_app_id: 1,
            authorization_service_token: Some("registry".to_owned()),
            platform_admin_authorization_service_token: Some("platform".to_owned()),
            artifact_admin_authorization_service_token: Some("artifact".to_owned()),
            build_cache_admin_authorization_service_token: Some("build-cache".to_owned()),
            github_client_id: None,
            github_client_secret: None,
            dashboard_password: None,
            cookie_secure: true,
            cookie_path: "/".to_owned(),
            public_origin: Some("https://vapor.example".to_owned()),
        }
    }

    #[test]
    fn audiences_use_distinct_service_tokens() {
        let config = config();
        assert_eq!(
            service_token_for_audience(&config, "vapor-registry"),
            Some("registry")
        );
        assert_eq!(
            service_token_for_audience(&config, "vapor-platform-admin"),
            Some("platform")
        );
        assert_eq!(
            service_token_for_audience(&config, "vapor-artifact-admin"),
            Some("artifact")
        );
        assert_eq!(
            service_token_for_audience(&config, "vapor-build-cache-admin"),
            Some("build-cache")
        );
        assert_eq!(
            service_token_for_audience(&config, "vapor-content-upload"),
            None
        );
        assert_eq!(service_token_for_audience(&config, "vapor-platform"), None);
    }

    #[test]
    fn platform_audience_is_disabled_without_its_dedicated_token() {
        let mut config = config();
        config.platform_admin_authorization_service_token = None;
        assert_eq!(
            service_token_for_audience(&config, "vapor-platform-admin"),
            None
        );
    }

    #[test]
    fn artifact_admin_audience_is_disabled_without_its_dedicated_token() {
        let mut config = config();
        config.artifact_admin_authorization_service_token = None;
        assert_eq!(
            service_token_for_audience(&config, "vapor-artifact-admin"),
            None
        );
    }

    #[test]
    fn build_cache_admin_audience_is_disabled_without_its_dedicated_token() {
        let mut config = config();
        config.build_cache_admin_authorization_service_token = None;
        assert_eq!(
            service_token_for_audience(&config, "vapor-build-cache-admin"),
            None
        );
    }
}
