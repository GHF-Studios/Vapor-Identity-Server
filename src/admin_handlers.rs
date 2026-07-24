use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::persistence::*;
use crate::types::*;
use crate::util::{authorized, text_response, valid_github_login, valid_steam_id64};

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

    let steam_id64 = request.steam_id64.trim();
    if !valid_steam_id64(steam_id64) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid SteamID64");
    }
    let github_login = request.github_login.trim();
    if !valid_github_login(github_login) {
        return text_response(StatusCode::BAD_REQUEST, "identity: invalid GitHub login");
    }

    let profile_id =
        match profile_id_by_linked_identities(&state.pool, steam_id64, github_login).await {
            Ok(Some(profile_id)) => profile_id,
            Ok(None) => {
                return text_response(
                    StatusCode::NOT_FOUND,
                    "identity: linked Steam/GitHub developer profile not found",
                );
            }
            Err(error) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("identity: failed to resolve linked developer profile: {error}"),
                );
            }
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
            role: role.to_string(),
            steam_id64: steam_id64.to_string(),
            github_login: github_login.to_string(),
            granted,
        }),
    )
        .into_response()
}
