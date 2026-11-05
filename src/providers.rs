use axum::http::StatusCode;
use axum::response::Response;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde_json::Value;
use std::collections::HashMap;

use crate::config::STEAM_OPENID_ENDPOINT;
use crate::types::{GitHubAccessTokenResponse, GitHubUser};
use crate::util::{steam_id_from_openid_claim, steam_id_from_response, text_response};

#[derive(Clone, Copy, Debug)]
pub(crate) struct SteamAppOwnership {
    pub(crate) active: bool,
    pub(crate) permanent: bool,
}

const MAX_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_STEAM_OPENID_PARAMS: usize = 32;
const MAX_STEAM_OPENID_PARAM_BYTES: usize = 8 * 1024;

pub(crate) fn provider_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Vapor-Identity-Server/0.1")
        .build()
}

async fn read_bounded_provider_body(mut response: reqwest::Response) -> Result<Vec<u8>, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{
        provider_http_client, read_bounded_provider_body, verify_steam_openid,
        MAX_PROVIDER_RESPONSE_BYTES,
    };
    use axum::routing::get;
    use axum::{http::StatusCode, Router};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    #[tokio::test]
    async fn provider_response_body_is_bounded() {
        let app = Router::new().route(
            "/body",
            get(|| async { "x".repeat(MAX_PROVIDER_RESPONSE_BYTES + 1) }),
        );
        let (origin, server) = serve(app).await;
        let response = reqwest::Client::new()
            .get(format!("{origin}/body"))
            .send()
            .await
            .unwrap();

        assert!(read_bounded_provider_body(response).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn provider_client_does_not_follow_redirects() {
        let target_hits = Arc::new(AtomicUsize::new(0));
        let target_hits_route = target_hits.clone();
        let app = Router::new()
            .route(
                "/redirect",
                get(|| async {
                    (
                        StatusCode::FOUND,
                        [(axum::http::header::LOCATION, "/target")],
                    )
                }),
            )
            .route(
                "/target",
                get(move || {
                    let target_hits = target_hits_route.clone();
                    async move {
                        target_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            );
        let (origin, server) = serve(app).await;

        let response = provider_http_client()
            .unwrap()
            .get(format!("{origin}/redirect"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(target_hits.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn steam_openid_input_is_bounded_before_forwarding() {
        let params = HashMap::from([("untrusted".to_owned(), "x".repeat(9 * 1024))]);

        let response = verify_steam_openid(&reqwest::Client::new(), &params)
            .await
            .unwrap_err();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

pub(crate) async fn check_steam_app_ownership(
    http: &reqwest::Client,
    publisher_key: &str,
    steam_id64: &str,
    app_id: u32,
) -> Result<SteamAppOwnership, ()> {
    let app_id = app_id.to_string();
    let response = http
        .get("https://partner.steam-api.com/ISteamUser/CheckAppOwnership/v4/")
        .query(&[
            ("key", publisher_key),
            ("steamid", steam_id64),
            ("appid", app_id.as_str()),
        ])
        .send()
        .await
        .map_err(|_| ())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(());
    }

    let body = read_bounded_provider_body(response).await?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| ())?;
    let ownership = body.get("appownership").unwrap_or(&body);
    let active = ownership
        .get("ownsapp")
        .and_then(Value::as_bool)
        .ok_or(())?;
    let permanent = ownership
        .get("permanent")
        .and_then(Value::as_bool)
        .ok_or(())?;
    let canceled = ownership
        .get("usercanceled")
        .and_then(Value::as_bool)
        .ok_or(())?;

    Ok(SteamAppOwnership {
        active: active && !canceled,
        permanent: active && permanent && !canceled,
    })
}

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
        .map_err(|_| {
            text_response(
                StatusCode::BAD_GATEWAY,
                "identity: Steam verification request failed",
            )
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: Steam rejected ticket",
        ));
    }

    let body = read_bounded_provider_body(response)
        .await
        .map_err(|_| text_response(StatusCode::BAD_GATEWAY, "identity: invalid Steam response"))?;
    let body: Value = serde_json::from_slice(&body)
        .map_err(|_| text_response(StatusCode::BAD_GATEWAY, "identity: invalid Steam response"))?;
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
        .map_err(|_| {
            text_response(
                StatusCode::BAD_GATEWAY,
                "identity: GitHub verification request failed",
            )
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub rejected token",
        ));
    }

    let body = read_bounded_provider_body(response)
        .await
        .map_err(|_| text_response(StatusCode::BAD_GATEWAY, "identity: invalid GitHub response"))?;
    serde_json::from_slice::<GitHubUser>(&body)
        .map_err(|_| text_response(StatusCode::BAD_GATEWAY, "identity: invalid GitHub response"))
}

pub(crate) async fn verify_steam_openid(
    http: &reqwest::Client,
    params: &HashMap<String, String>,
) -> Result<String, Response> {
    if params.len() > MAX_STEAM_OPENID_PARAMS
        || params
            .iter()
            .any(|(key, value)| key.len() > 128 || value.len() > 2048)
        || params.iter().fold(0usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        }) > MAX_STEAM_OPENID_PARAM_BYTES
    {
        return Err(text_response(
            StatusCode::BAD_REQUEST,
            "identity: Steam OpenID response is too large",
        ));
    }
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
        .map_err(|_| {
            text_response(
                StatusCode::BAD_GATEWAY,
                "identity: Steam OpenID verification failed",
            )
        })?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(text_response(
            StatusCode::BAD_GATEWAY,
            "identity: Steam OpenID verification returned an unexpected status",
        ));
    }
    let body = read_bounded_provider_body(response).await.map_err(|_| {
        text_response(
            StatusCode::BAD_GATEWAY,
            "identity: invalid Steam OpenID response",
        )
    })?;
    let body = String::from_utf8(body).map_err(|_| {
        text_response(
            StatusCode::BAD_GATEWAY,
            "identity: invalid Steam OpenID response",
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
        .map_err(|_| {
            text_response(
                StatusCode::BAD_GATEWAY,
                "identity: GitHub code exchange failed",
            )
        })?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub rejected code",
        ));
    }
    let body = read_bounded_provider_body(response).await.map_err(|_| {
        text_response(
            StatusCode::BAD_GATEWAY,
            "identity: invalid GitHub code exchange response",
        )
    })?;
    let token_response: GitHubAccessTokenResponse =
        serde_json::from_slice(&body).map_err(|_| {
            text_response(
                StatusCode::BAD_GATEWAY,
                "identity: invalid GitHub code exchange response",
            )
        })?;
    if token_response.error.is_some() {
        return Err(text_response(
            StatusCode::UNAUTHORIZED,
            "identity: GitHub code exchange was rejected",
        ));
    }
    token_response
        .access_token
        .filter(|token| !token.is_empty() && token.len() <= 4096)
        .ok_or_else(|| {
            text_response(
                StatusCode::BAD_GATEWAY,
                "identity: GitHub code exchange did not return a valid access token",
            )
        })
}
