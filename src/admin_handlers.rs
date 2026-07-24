use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::persistence::*;
use crate::types::*;
use crate::util::{
    authorized, text_response, valid_github_login, valid_profile_id, valid_steam_id64,
};

pub(crate) async fn list_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match admin_or_root_authorized(&state, &headers).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                "missing or invalid admin token/root session\n".to_string(),
            );
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to validate authorization: {error}\n"),
            );
        }
    }

    let body = match profile_listing(&state.pool).await {
        Ok(body) => body,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to list profiles: {error}\n"),
            );
        }
    };
    (StatusCode::OK, body)
}

pub(crate) async fn grant_root_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<GrantRootRequest>,
) -> Response {
    if !authorized(&headers, &state.admin_token) {
        return text_response(StatusCode::UNAUTHORIZED, "missing or invalid admin token");
    }
    if !valid_profile_id(&request.profile_id) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid profile id");
    }
    match profile_has_dual_identity(&state.pool, &request.profile_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: root role requires linked Steam and GitHub identities",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate profile identity state: {error}"),
            );
        }
    }
    let granted = match grant_root(&state.pool, &request.profile_id, None).await {
        Ok(granted) => granted,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to grant root role: {error}"),
            );
        }
    };
    (
        StatusCode::OK,
        Json(GrantRootResponse {
            profile_id: request.profile_id,
            role: "root",
            granted,
        }),
    )
        .into_response()
}

pub(crate) async fn grant_profile_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<GrantRoleRequest>,
) -> Response {
    if !authorized(&headers, &state.admin_token) {
        return text_response(StatusCode::UNAUTHORIZED, "missing or invalid admin token");
    }

    let role = request.role.trim();
    if !valid_elevated_role(role) {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: role must be root or content-developer",
        );
    }

    let profile_id = request
        .profile_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let steam_id64 = request
        .steam_id64
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let github_login = request
        .github_login
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let selector_count = usize::from(profile_id.is_some())
        + usize::from(steam_id64.is_some())
        + usize::from(github_login.is_some());
    if selector_count != 1 {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: provide exactly one of profile_id, steam_id64, or github_login",
        );
    }

    let profile_id = if let Some(profile_id) = profile_id {
        if !valid_profile_id(profile_id) {
            return text_response(StatusCode::BAD_REQUEST, "identity: invalid profile id");
        }
        match profile_by_id(&state.pool, profile_id).await {
            Ok(Some(_profile)) => profile_id.to_string(),
            Ok(None) => return text_response(StatusCode::NOT_FOUND, "identity: profile not found"),
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to read profile: {error}"),
                );
            }
        }
    } else if let Some(steam_id64) = steam_id64 {
        if !valid_steam_id64(steam_id64) {
            return text_response(StatusCode::BAD_REQUEST, "identity: invalid SteamID64");
        }
        match profile_id_by_steam_id64(&state.pool, steam_id64).await {
            Ok(Some(profile_id)) => profile_id,
            Ok(None) => {
                return text_response(StatusCode::NOT_FOUND, "identity: Steam profile not found");
            }
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to resolve Steam profile: {error}"),
                );
            }
        }
    } else if let Some(github_login) = github_login {
        if !valid_github_login(github_login) {
            return text_response(StatusCode::BAD_REQUEST, "identity: invalid GitHub login");
        }
        match profile_id_by_github_login(&state.pool, github_login).await {
            Ok(Some(profile_id)) => profile_id,
            Ok(None) => {
                return text_response(StatusCode::NOT_FOUND, "identity: GitHub profile not found");
            }
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to resolve GitHub profile: {error}"),
                );
            }
        }
    } else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "identity: provide exactly one of profile_id, steam_id64, or github_login",
        );
    };

    match profile_has_dual_identity(&state.pool, &profile_id).await {
        Ok(true) => {}
        Ok(false) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                "identity: elevated roles require linked Steam and GitHub identities",
            );
        }
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to validate profile identity state: {error}"),
            );
        }
    }

    let granted = match grant_role(&state.pool, &profile_id, role, None).await {
        Ok(granted) => granted,
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("identity: failed to grant profile role: {error}"),
            );
        }
    };
    (
        StatusCode::OK,
        Json(GrantRoleResponse {
            profile_id,
            role: role.to_string(),
            granted,
        }),
    )
        .into_response()
}
