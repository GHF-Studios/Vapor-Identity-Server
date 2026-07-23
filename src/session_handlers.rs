use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use reqwest::header::{ACCEPT, USER_AGENT};

use crate::config::{AUTH_ATTEMPT_TTL_SECONDS, DASHBOARD_SESSION_TTL_SECONDS};
use crate::persistence::*;
use crate::providers::{verify_github_access_token, verify_steam_ticket};
use crate::types::*;
use crate::util::{
    authorized, github_device_ready, new_auth_attempt_id, session_cookie, text_response,
    unix_now_i64, valid_auth_attempt_id, valid_hex_ticket,
};
pub(crate) async fn start_auth_attempt(
    State(state): State<AppState>,
    Json(request): Json<StartAuthAttemptRequest>,
) -> Response {
    let purpose = request
        .purpose
        .as_deref()
        .unwrap_or("root-dashboard")
        .trim();
    if purpose != "root-dashboard" {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: unsupported auth attempt purpose",
        );
    }

    let now = unix_now_i64();
    let auth_attempt_id = new_auth_attempt_id();
    let expires_at_unix = now + AUTH_ATTEMPT_TTL_SECONDS;
    if let Err(error) =
        create_auth_attempt(&state.pool, &auth_attempt_id, purpose, now, expires_at_unix).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to create auth attempt: {error}"),
        );
    }

    (
        StatusCode::CREATED,
        Json(StartAuthAttemptResponse {
            auth_attempt_id,
            purpose: purpose.to_string(),
            expires_at_unix,
            expires_in_seconds: AUTH_ATTEMPT_TTL_SECONDS,
            steam_required: true,
            github_required: true,
            dashboard_session_ttl_seconds: DASHBOARD_SESSION_TTL_SECONDS,
        }),
    )
        .into_response()
}

pub(crate) async fn auth_session_steam_ticket(
    State(state): State<AppState>,
    Json(request): Json<SteamSessionTicketRequest>,
) -> Response {
    let Some(key) = state.config.steam_web_api_key.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: Steam Web API key is not configured",
        );
    };
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    match auth_attempt_is_active(&state.pool, &request.auth_attempt_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read auth attempt: {error}"),
            );
        }
    }
    if !valid_hex_ticket(&request.ticket_hex) {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: invalid Steam ticket hex",
        );
    }

    let identity = request
        .identity
        .as_deref()
        .unwrap_or(&state.config.steam_auth_identity);
    let steam_id64 = match verify_steam_ticket(
        &state.http,
        key,
        state.config.steam_app_id,
        identity,
        &request.ticket_hex,
    )
    .await
    {
        Ok(steam_id64) => steam_id64,
        Err(response) => return response,
    };

    if let Err(error) =
        record_auth_attempt_steam(&state.pool, &request.auth_attempt_id, &steam_id64).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record Steam proof: {error}"),
        );
    }

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id: String::new(),
            provider: "steam",
            steam_id64: Some(steam_id64),
            github_user_id: None,
            github_login: None,
        }),
    )
        .into_response()
}

pub(crate) async fn auth_session_github_token(
    State(state): State<AppState>,
    Json(request): Json<GitHubSessionTokenRequest>,
) -> Response {
    if !github_device_ready(&state.config) {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    }
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    match auth_attempt_is_active(&state.pool, &request.auth_attempt_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read auth attempt: {error}"),
            );
        }
    }
    if request.access_token.trim().is_empty() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: empty GitHub access token",
        );
    }

    let user = match verify_github_access_token(&state.http, request.access_token.trim()).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(error) =
        record_auth_attempt_github(&state.pool, &request.auth_attempt_id, &user).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record GitHub proof: {error}"),
        );
    }

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id: String::new(),
            provider: "github",
            steam_id64: None,
            github_user_id: Some(user.id),
            github_login: Some(user.login),
        }),
    )
        .into_response()
}

pub(crate) async fn auth_session_github_device_start(
    State(state): State<AppState>,
    Json(request): Json<GitHubDeviceStartRequest>,
) -> Response {
    let Some(client_id) = state.config.github_client_id.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    };
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    match auth_attempt_is_active(&state.pool, &request.auth_attempt_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read auth attempt: {error}"),
            );
        }
    }

    let response = match state
        .http
        .post("https://github.com/login/device/code")
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&[("client_id", client_id), ("scope", "read:user")])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub device-code request failed: {error}"),
            );
        }
    };
    if !response.status().is_success() {
        return text_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "identity: GitHub rejected device-code request with {}",
                response.status()
            ),
        );
    }
    let device = match response.json::<GitHubDeviceCodeResponse>().await {
        Ok(device) => device,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub device-code response: {error}"),
            );
        }
    };
    let now = unix_now_i64();
    let interval = device.interval.unwrap_or(5).max(5);
    let github_expires_at = now + device.expires_in.max(0);
    let expires_at_unix = github_expires_at.min(now + AUTH_ATTEMPT_TTL_SECONDS);
    if let Err(error) = record_github_device_flow(
        &state.pool,
        &request.auth_attempt_id,
        &device.device_code,
        interval,
        expires_at_unix,
        now + interval,
    )
    .await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record GitHub device flow: {error}"),
        );
    }

    (
        StatusCode::CREATED,
        Json(GitHubDeviceStartResponse {
            auth_attempt_id: request.auth_attempt_id,
            user_code: device.user_code,
            verification_uri: device.verification_uri,
            verification_uri_complete: device.verification_uri_complete,
            expires_at_unix,
            poll_interval_seconds: interval,
        }),
    )
        .into_response()
}

pub(crate) async fn auth_session_github_device_poll(
    State(state): State<AppState>,
    Json(request): Json<GitHubDevicePollRequest>,
) -> Response {
    let Some(client_id) = state.config.github_client_id.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    };
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    let Some(device) = (match github_device_flow(&state.pool, &request.auth_attempt_id).await {
        Ok(device) => device,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read GitHub device flow: {error}"),
            );
        }
    }) else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub device flow is missing or expired",
        );
    };
    let now = unix_now_i64();
    if now < device.next_poll_at_unix {
        return (
            StatusCode::TOO_EARLY,
            Json(GitHubDevicePollResponse {
                auth_attempt_id: request.auth_attempt_id,
                status: "pending",
                github_login: None,
                github_user_id: None,
                next_poll_at_unix: Some(device.next_poll_at_unix),
                poll_interval_seconds: Some(device.interval_seconds),
            }),
        )
            .into_response();
    }

    let response = match state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&[
            ("client_id", client_id),
            ("device_code", device.device_code.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub device poll failed: {error}"),
            );
        }
    };
    if !response.status().is_success() {
        return text_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "identity: GitHub rejected device poll with {}",
                response.status()
            ),
        );
    }
    let token_response = match response.json::<GitHubAccessTokenResponse>().await {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub device poll response: {error}"),
            );
        }
    };
    if let Some(error) = token_response.error.as_deref() {
        let interval = match error {
            "slow_down" => device.interval_seconds + 5,
            _ => token_response
                .interval
                .unwrap_or(device.interval_seconds)
                .max(5),
        };
        let next_poll_at_unix = now + interval;
        if let Err(error) = update_github_device_poll(
            &state.pool,
            &request.auth_attempt_id,
            interval,
            next_poll_at_unix,
        )
        .await
        {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to update GitHub device poll state: {error}"),
            );
        }
        let status = match error {
            "authorization_pending" | "slow_down" => "pending",
            "expired_token" | "token_expired" => "expired",
            "access_denied" => "denied",
            _ => "failed",
        };
        let code = match status {
            "pending" => StatusCode::ACCEPTED,
            "expired" => StatusCode::GONE,
            "denied" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_GATEWAY,
        };
        return (
            code,
            Json(GitHubDevicePollResponse {
                auth_attempt_id: request.auth_attempt_id,
                status,
                github_login: None,
                github_user_id: None,
                next_poll_at_unix: Some(next_poll_at_unix),
                poll_interval_seconds: Some(interval),
            }),
        )
            .into_response();
    }
    let Some(access_token) = token_response.access_token.as_deref() else {
        return text_response(
            StatusCode::BAD_GATEWAY,
            "identity: GitHub device poll did not return an access token",
        );
    };
    if token_response
        .token_type
        .as_deref()
        .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
    {
        return text_response(
            StatusCode::BAD_GATEWAY,
            "identity: GitHub device poll returned unsupported token type",
        );
    }
    let user = match verify_github_access_token(&state.http, access_token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(error) =
        record_auth_attempt_github(&state.pool, &request.auth_attempt_id, &user).await
    {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to record GitHub proof: {error}"),
        );
    }
    if let Err(error) = clear_github_device_flow(&state.pool, &request.auth_attempt_id).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to clear GitHub device flow: {error}"),
        );
    }

    (
        StatusCode::OK,
        Json(GitHubDevicePollResponse {
            auth_attempt_id: request.auth_attempt_id,
            status: "authorized",
            github_login: Some(user.login),
            github_user_id: Some(user.id),
            next_poll_at_unix: None,
            poll_interval_seconds: None,
        }),
    )
        .into_response()
}

pub(crate) async fn finish_auth_attempt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FinishAuthAttemptRequest>,
) -> Response {
    if !valid_auth_attempt_id(&request.auth_attempt_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid auth attempt id");
    }
    let linked = match link_verified_auth_attempt(&state.pool, &request.auth_attempt_id).await {
        Ok(linked) => linked,
        Err(AuthFinishError::InvalidAttempt) => {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "identity: auth attempt is missing, expired, or already consumed",
            );
        }
        Err(AuthFinishError::MissingSteam) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: auth attempt has no verified Steam proof",
            );
        }
        Err(AuthFinishError::MissingGitHub) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: auth attempt has no verified GitHub proof",
            );
        }
        Err(AuthFinishError::ConflictingProfiles) => {
            return text_response(
                StatusCode::CONFLICT,
                "identity: verified Steam and GitHub accounts belong to different profiles",
            );
        }
        Err(AuthFinishError::Database(error)) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to link verified identity: {error}"),
            );
        }
    };

    let mut has_root = match profile_has_root_role(&state.pool, &linked.profile_id).await {
        Ok(has_root) => has_root,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read profile roles: {error}"),
            );
        }
    };
    if !has_root
        && request.bootstrap_first_root.unwrap_or(false)
        && authorized(&headers, &state.admin_token)
    {
        match active_root_profile_count(&state.pool).await {
            Ok(0) => {
                if let Err(error) = grant_root(&state.pool, &linked.profile_id, None).await {
                    return text_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("identity: failed to bootstrap root role: {error}"),
                    );
                }
                has_root = true;
            }
            Ok(_) => {}
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to read root role state: {error}"),
                );
            }
        }
    }
    if !has_root {
        return text_response(
            StatusCode::FORBIDDEN,
            "identity: verified profile does not have root role",
        );
    }

    let (session_id, token, expires_at_unix) =
        match create_identity_session(&state.pool, &linked.profile_id).await {
            Ok(session) => session,
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to create dashboard session: {error}"),
                );
            }
        };
    if let Err(error) = consume_auth_attempt(&state.pool, &request.auth_attempt_id).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("identity: failed to consume auth attempt: {error}"),
        );
    }
    let roles = match active_roles(&state.pool, &linked.profile_id).await {
        Ok(roles) => roles,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to read session roles: {error}"),
            );
        }
    };

    (
        StatusCode::OK,
        [(
            SET_COOKIE,
            session_cookie(&state.config, &token, DASHBOARD_SESSION_TTL_SECONDS),
        )],
        Json(FinishAuthAttemptResponse {
            session_id,
            profile_id: linked.profile_id,
            expires_at_unix,
            root_authorized: true,
            roles,
            steam_id64: linked.steam_id64,
            github_login: linked.github_login,
        }),
    )
        .into_response()
}
