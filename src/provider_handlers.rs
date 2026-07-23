use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde_json::Value;

use crate::persistence::*;
use crate::types::*;
use crate::util::{steam_id_from_response, text_response, valid_hex_ticket};
pub(crate) async fn auth_steam_ticket(
    State(state): State<AppState>,
    Json(request): Json<SteamTicketRequest>,
) -> Response {
    let Some(key) = state.config.steam_web_api_key.as_deref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: Steam Web API key is not configured",
        );
    };
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
    let app_id = state.config.steam_app_id.to_string();
    let response = match state
        .http
        .get("https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/")
        .query(&[
            ("key", key),
            ("appid", app_id.as_str()),
            ("ticket", request.ticket_hex.as_str()),
            ("identity", identity),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: Steam verification request failed: {error}"),
            );
        }
    };

    if !response.status().is_success() {
        return text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: Steam rejected ticket with {}", response.status()),
        );
    }

    let body = match response.json::<Value>().await {
        Ok(body) => body,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode Steam response: {error}"),
            );
        }
    };
    let Some(steam_id64) = steam_id_from_response(&body) else {
        return text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam response did not contain a verified steamid",
        );
    };

    let profile_id = match link_steam_account(&state.pool, &steam_id64).await {
        Ok(profile_id) => profile_id,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to persist Steam identity: {error}"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(IdentityAuthResponse {
            profile_id,
            provider: "steam",
            steam_id64: Some(steam_id64),
            github_user_id: None,
            github_login: None,
        }),
    )
        .into_response()
}

pub(crate) async fn auth_github_token(
    State(state): State<AppState>,
    Json(request): Json<GitHubTokenRequest>,
) -> Response {
    if state.config.github_client_id.is_none() {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity: GitHub client ID is not configured",
        );
    }
    if request.access_token.trim().is_empty() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: empty GitHub access token",
        );
    }

    let response = match state
        .http
        .get("https://api.github.com/user")
        .bearer_auth(request.access_token.trim())
        .header(ACCEPT, "application/vnd.github+json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub verification request failed: {error}"),
            );
        }
    };

    if !response.status().is_success() {
        return text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub rejected token with {}", response.status()),
        );
    }

    let user = match response.json::<GitHubUser>().await {
        Ok(user) => user,
        Err(error) => {
            return text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub response: {error}"),
            );
        }
    };

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
