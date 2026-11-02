use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::permission_requests::{create_permission_request, CreatePermissionRequest};
use crate::persistence::*;
use crate::types::*;
use crate::util::{authorized, text_response, valid_github_login, valid_steam_id64};

pub(crate) struct RoleGrantError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl RoleGrantError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

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

pub(crate) async fn list_audit_events(
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

    let body = match audit_listing(&state.pool).await {
        Ok(body) => body,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("identity: failed to list audit events: {error}\n"),
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
    let actor_profile_id = match role_grant_actor(&state, &headers).await {
        Ok(actor_profile_id) => actor_profile_id,
        Err(error) => {
            return text_response(error.status, &format!("identity: {}", error.message));
        }
    };

    if actor_profile_id.is_some() {
        return create_permission_request(
            State(state),
            headers,
            Json(CreatePermissionRequest {
                action: "grant".to_string(),
                role: request.role,
                steam_id64: request.steam_id64,
                github_login: request.github_login,
            }),
        )
        .await;
    }

    match grant_role_request(&state, &request, actor_profile_id.as_deref()).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => text_response(error.status, &format!("identity: {}", error.message)),
    }
}

pub(crate) async fn revoke_profile_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeRoleRequest>,
) -> Response {
    let actor_profile_id = match role_grant_actor(&state, &headers).await {
        Ok(actor_profile_id) => actor_profile_id,
        Err(error) => {
            return text_response(error.status, &format!("identity: {}", error.message));
        }
    };

    if actor_profile_id.is_some() {
        return create_permission_request(
            State(state),
            headers,
            Json(CreatePermissionRequest {
                action: "revoke".to_string(),
                role: request.role,
                steam_id64: request.steam_id64,
                github_login: request.github_login,
            }),
        )
        .await;
    }

    match revoke_role_request(&state, &request, actor_profile_id.as_deref()).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => text_response(error.status, &format!("identity: {}", error.message)),
    }
}

pub(crate) async fn role_grant_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, RoleGrantError> {
    match root_session_profile_id(&state.pool, headers).await {
        Ok(Some(profile_id)) => return Ok(Some(profile_id)),
        Ok(None) => {}
        Err(error) => {
            return Err(RoleGrantError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to validate root session: {error}"),
            ));
        }
    };
    if authorized(headers, &state.admin_token) {
        return Ok(None);
    }
    Err(RoleGrantError::new(
        StatusCode::UNAUTHORIZED,
        "missing or invalid admin token/root session",
    ))
}

pub(crate) async fn grant_role_request(
    state: &AppState,
    request: &GrantRoleRequest,
    actor_profile_id: Option<&str>,
) -> Result<GrantRoleResponse, RoleGrantError> {
    let role = request.role.trim();
    if !valid_elevated_role(role) {
        return Err(RoleGrantError::new(
            StatusCode::BAD_REQUEST,
            "role must be root or content-developer",
        ));
    }

    let steam_id64 = request.steam_id64.trim();
    if !valid_steam_id64(steam_id64) {
        return Err(RoleGrantError::new(
            StatusCode::BAD_REQUEST,
            "invalid SteamID64",
        ));
    }
    let github_login = request.github_login.trim();
    if !valid_github_login(github_login) {
        return Err(RoleGrantError::new(
            StatusCode::BAD_REQUEST,
            "invalid GitHub login",
        ));
    }

    let profile_id =
        match profile_id_by_linked_identities(&state.pool, steam_id64, github_login).await {
            Ok(Some(profile_id)) => profile_id,
            Ok(None) => {
                return Err(RoleGrantError::new(
                    StatusCode::NOT_FOUND,
                    "linked Steam/GitHub developer profile not found",
                ));
            }
            Err(error) => {
                return Err(RoleGrantError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to resolve linked developer profile: {error}"),
                ));
            }
        };
    match profile_has_dual_identity(&state.pool, &profile_id).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(RoleGrantError::new(
                StatusCode::BAD_REQUEST,
                "elevated roles require linked Steam and GitHub identities",
            ));
        }
        Err(error) => {
            return Err(RoleGrantError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to validate profile identity state: {error}"),
            ));
        }
    }

    let granted = match grant_role(&state.pool, &profile_id, role, actor_profile_id).await {
        Ok(granted) => granted,
        Err(error) => {
            return Err(RoleGrantError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to grant profile role: {error}"),
            ));
        }
    };
    Ok(GrantRoleResponse {
        role: role.to_string(),
        steam_id64: steam_id64.to_string(),
        github_login: github_login.to_string(),
        granted,
    })
}

pub(crate) async fn revoke_role_request(
    state: &AppState,
    request: &RevokeRoleRequest,
    actor_profile_id: Option<&str>,
) -> Result<RevokeRoleResponse, RoleGrantError> {
    let role = request.role.trim();
    if !valid_elevated_role(role) {
        return Err(RoleGrantError::new(
            StatusCode::BAD_REQUEST,
            "role must be root or content-developer",
        ));
    }

    let steam_id64 = request.steam_id64.trim();
    if !valid_steam_id64(steam_id64) {
        return Err(RoleGrantError::new(
            StatusCode::BAD_REQUEST,
            "invalid SteamID64",
        ));
    }
    let github_login = request.github_login.trim();
    if !valid_github_login(github_login) {
        return Err(RoleGrantError::new(
            StatusCode::BAD_REQUEST,
            "invalid GitHub login",
        ));
    }

    let profile_id =
        match profile_id_by_linked_identities(&state.pool, steam_id64, github_login).await {
            Ok(Some(profile_id)) => profile_id,
            Ok(None) => {
                return Err(RoleGrantError::new(
                    StatusCode::NOT_FOUND,
                    "linked Steam/GitHub developer profile not found",
                ));
            }
            Err(error) => {
                return Err(RoleGrantError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to resolve linked developer profile: {error}"),
                ));
            }
        };
    match profile_has_dual_identity(&state.pool, &profile_id).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(RoleGrantError::new(
                StatusCode::BAD_REQUEST,
                "elevated roles require linked Steam and GitHub identities",
            ));
        }
        Err(error) => {
            return Err(RoleGrantError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to validate profile identity state: {error}"),
            ));
        }
    }

    if role == "content-developer" {
        match profile_has_root_role(&state.pool, &profile_id).await {
            Ok(true) => {
                return Err(RoleGrantError::new(
                    StatusCode::BAD_REQUEST,
                    "root implies content-developer; revoke root first to remove developer capability",
                ));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(RoleGrantError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to validate profile role state: {error}"),
                ));
            }
        }
    }

    let revoked = match revoke_role(&state.pool, &profile_id, role, actor_profile_id).await {
        Ok(revoked) => revoked,
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("last active root") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return Err(RoleGrantError::new(
                status,
                format!("failed to revoke profile role: {error}"),
            ));
        }
    };
    Ok(RevokeRoleResponse {
        role: role.to_string(),
        steam_id64: steam_id64.to_string(),
        github_login: github_login.to_string(),
        revoked,
    })
}
