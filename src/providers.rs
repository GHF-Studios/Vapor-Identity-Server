use axum::http::StatusCode;
use axum::response::Response;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde_json::Value;
use std::collections::HashMap;

use crate::config::STEAM_OPENID_ENDPOINT;
use crate::types::{GitHubAccessTokenResponse, GitHubUser};
use crate::util::{steam_id_from_openid_claim, steam_id_from_response, text_response};

pub(crate) async fn verify_steam_ticket(
    http: &reqwest::Client,
    key: &str,
    app_id: u32,
    identity: &str,
    ticket_hex: &str,
) -> Result<String, Response> {
    let app_id = app_id.to_string();
    let response = http
        .get("https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/")
        .query(&[
            ("key", key),
            ("appid", app_id.as_str()),
            ("ticket", ticket_hex),
            ("identity", identity),
        ])
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: Steam verification request failed: {error}"),
            )
        })?;

    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: Steam rejected ticket with {}", response.status()),
        ));
    }

    let body = response.json::<Value>().await.map_err(|error| {
        text_response(
            StatusCode::BAD_GATEWAY,
            &format!("identity: failed to decode Steam response: {error}"),
        )
    })?;
    steam_id_from_response(&body).ok_or_else(|| {
        text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam response did not contain a verified steamid",
        )
    })
}

pub(crate) async fn verify_github_access_token(
    http: &reqwest::Client,
    access_token: &str,
) -> Result<GitHubUser, Response> {
    let response = http
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header(ACCEPT, "application/vnd.github+json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub verification request failed: {error}"),
            )
        })?;

    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub rejected token with {}", response.status()),
        ));
    }

    response.json::<GitHubUser>().await.map_err(|error| {
        text_response(
            StatusCode::BAD_GATEWAY,
            &format!("identity: failed to decode GitHub response: {error}"),
        )
    })
}

pub(crate) async fn verify_steam_openid(
    http: &reqwest::Client,
    params: &HashMap<String, String>,
) -> Result<String, Response> {
    if params
        .get("openid.op_endpoint")
        .is_none_or(|value| value != STEAM_OPENID_ENDPOINT)
    {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID endpoint did not match Steam",
        ));
    }

    let claimed_id = params
        .get("openid.claimed_id")
        .ok_or_else(|| text_response(StatusCode::BAD_REQUEST, "identity: missing claimed_id"))?;
    let steam_id64 = steam_id_from_openid_claim(claimed_id).ok_or_else(|| {
        text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID claimed_id did not contain SteamID64",
        )
    })?;
    if params
        .get("openid.identity")
        .is_none_or(|identity| identity != claimed_id)
    {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID identity did not match claimed_id",
        ));
    }

    let mut form = Vec::new();
    for (key, value) in params {
        if key.starts_with("openid.") {
            if key == "openid.mode" {
                form.push((key.clone(), "check_authentication".to_string()));
            } else {
                form.push((key.clone(), value.clone()));
            }
        }
    }
    if !form.iter().any(|(key, _)| key == "openid.mode") {
        form.push((
            "openid.mode".to_string(),
            "check_authentication".to_string(),
        ));
    }

    let response = http
        .post(STEAM_OPENID_ENDPOINT)
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&form)
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: Steam OpenID verification failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "identity: Steam OpenID verification returned {}",
                response.status()
            ),
        ));
    }
    let body = response.text().await.map_err(|error| {
        text_response(
            StatusCode::BAD_GATEWAY,
            &format!("identity: failed to read Steam OpenID response: {error}"),
        )
    })?;
    if !body.lines().any(|line| line.trim() == "is_valid:true") {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam OpenID response was not valid",
        ));
    }

    Ok(steam_id64)
}

pub(crate) async fn exchange_github_web_code(
    http: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, Response> {
    let response = http
        .post("https://github.com/login/oauth/access_token")
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Vapor-Identity-Server/0.1")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: GitHub code exchange failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub rejected code with {}", response.status()),
        ));
    }
    let token_response = response
        .json::<GitHubAccessTokenResponse>()
        .await
        .map_err(|error| {
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("identity: failed to decode GitHub code exchange response: {error}"),
            )
        })?;
    if let Some(error) = token_response.error.as_deref() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            &format!("identity: GitHub code exchange returned {error}"),
        ));
    }
    token_response.access_token.ok_or_else(|| {
        text_response(
            StatusCode::BAD_GATEWAY,
            "identity: GitHub code exchange did not return an access token",
        )
    })
}
