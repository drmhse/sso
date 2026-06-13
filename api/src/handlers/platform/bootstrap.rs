use crate::auth::jwt::JwtService;
use crate::error::{AppError, Result};
use crate::handlers::auth::session::RefreshTokenResponse;
use crate::middleware::{AuthUser, RequestInfo};
use crate::state::AppState;
use crate::store::{sessions::SessionStore, users::UserStore, DB};
use axum::{extract::State, Extension, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ManagedConfigResponse {
    pub config: Value,
    pub config_path: String,
    pub apply_command_configured: bool,
    pub status: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapLoginRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ApplyManagedConfigResponse {
    pub scheduled: bool,
    pub message: String,
}

pub async fn get_managed_config(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<ManagedConfigResponse>> {
    require_platform_owner(&auth_user)?;
    let paths = managed_paths(&state)?;
    Ok(Json(load_managed_config_response(
        &paths,
        state.config.managed_request_path.is_some(),
    )?))
}

pub async fn update_managed_config(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(config): Json<Value>,
) -> Result<Json<ManagedConfigResponse>> {
    require_platform_owner(&auth_user)?;
    let paths = managed_paths(&state)?;
    let current_config = read_json_file(&paths.config_path)?;
    validate_managed_config(&config, &current_config)?;
    write_json_file(&paths.config_path, &config)?;

    Ok(Json(load_managed_config_response(
        &paths,
        state.config.managed_request_path.is_some(),
    )?))
}

pub async fn apply_managed_config(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<ApplyManagedConfigResponse>> {
    require_platform_owner(&auth_user)?;

    let paths = managed_paths(&state)?;
    let request_path =
        state.config.managed_request_path.clone().ok_or_else(|| {
            AppError::NotFound("Managed apply queue is not configured".to_string())
        })?;

    let queued_status = json!({
        "status": "queued",
        "message": "AuthOS reload has been queued.",
        "updated_at": Utc::now().to_rfc3339(),
    });
    if let Some(status_path) = paths.status_path.as_ref() {
        write_json_file(status_path, &queued_status)?;
    }

    write_json_file(
        &request_path,
        &json!({
            "requested_at": Utc::now().to_rfc3339(),
            "requested_by": auth_user.user.id,
        }),
    )?;

    Ok(Json(ApplyManagedConfigResponse {
        scheduled: true,
        message: "AuthOS reload queued. Refresh this page after the service comes back."
            .to_string(),
    }))
}

pub async fn bootstrap_login(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Json(req): Json<BootstrapLoginRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    if req.token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Bootstrap token is required".to_string(),
        ));
    }

    let paths = managed_paths(&state)?;
    let mut managed_state = read_json_file(&paths.state_path)?;
    let token_state = managed_state
        .get_mut("bootstrap_login")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| AppError::Unauthorized("Bootstrap login is not available".to_string()))?;

    let stored_token = token_state
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Unauthorized("Bootstrap login is not available".to_string()))?;
    if stored_token != req.token {
        return Err(AppError::Unauthorized(
            "Invalid bootstrap login token".to_string(),
        ));
    }

    if token_state.get("used_at").and_then(Value::as_str).is_some() {
        return Err(AppError::Unauthorized(
            "This bootstrap login link has already been used".to_string(),
        ));
    }

    if let Some(expires_at) = token_state.get("expires_at").and_then(Value::as_str) {
        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| AppError::Unauthorized("Bootstrap login token is invalid".to_string()))?;
        if expires_at.with_timezone(&Utc) <= Utc::now() {
            return Err(AppError::Unauthorized(
                "This bootstrap login link has expired".to_string(),
            ));
        }
    }

    let owner_email = state.config.platform_owner_email.as_ref().ok_or_else(|| {
        AppError::Unauthorized("Platform owner email is not configured".to_string())
    })?;
    let user = UserStore::find_by_email_with_context(DB::Conn(&state.db), owner_email, None)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Platform owner user does not exist".to_string()))?;

    if !user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Configured owner does not have platform access".to_string(),
        ));
    }

    let access_token = state
        .jwt_service
        .create_token(&user.id, &user.email, true, None, None)?;
    let refresh_token = Uuid::new_v4().to_string();
    let expires_at =
        (Utc::now() + chrono::Duration::hours(state.config.jwt_expiration_hours)).naive_utc();
    let refresh_expires_at = (Utc::now() + chrono::Duration::days(30)).naive_utc();

    SessionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &JwtService::hash_token(&access_token),
        expires_at,
        Some(&refresh_token),
        Some(refresh_expires_at),
        None,
        None,
        None,
        Some(&request_info.user_agent),
        Some(&request_info.ip_address),
    )
    .await?;

    token_state.insert(
        "used_at".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    write_json_file(&paths.state_path, &managed_state)?;

    Ok(Json(RefreshTokenResponse {
        access_token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

struct ManagedPaths {
    config_path: String,
    state_path: String,
    status_path: Option<String>,
}

fn require_platform_owner(auth_user: &AuthUser) -> Result<()> {
    if auth_user.user.is_platform_owner {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ))
    }
}

fn managed_paths(state: &AppState) -> Result<ManagedPaths> {
    let config_path = state
        .config
        .managed_config_path
        .clone()
        .ok_or_else(|| AppError::NotFound("Managed config is not enabled".to_string()))?;
    let state_path = state
        .config
        .managed_state_path
        .clone()
        .ok_or_else(|| AppError::NotFound("Managed config state is not enabled".to_string()))?;

    Ok(ManagedPaths {
        config_path,
        state_path,
        status_path: state.config.managed_status_path.clone(),
    })
}

fn load_managed_config_response(
    paths: &ManagedPaths,
    apply_command_configured: bool,
) -> Result<ManagedConfigResponse> {
    let config = read_json_file(&paths.config_path)?;
    let status = paths
        .status_path
        .as_ref()
        .and_then(|path| read_json_file(path).ok());

    Ok(ManagedConfigResponse {
        config,
        config_path: paths.config_path.clone(),
        apply_command_configured,
        status,
    })
}

fn validate_managed_config(value: &Value, current: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        AppError::BadRequest("Managed config payload must be a JSON object".to_string())
    })?;
    if let Some(deployment) = object.get("deployment") {
        if !deployment.is_object() {
            return Err(AppError::BadRequest(
                "deployment must be a JSON object".to_string(),
            ));
        }
    }
    if let Some(platform_owner) = object.get("platformOwner") {
        if !platform_owner.is_object() {
            return Err(AppError::BadRequest(
                "platformOwner must be a JSON object".to_string(),
            ));
        }
    }
    reject_protected_change(
        current
            .get("standalone")
            .and_then(|value| value.get("dataDir")),
        object
            .get("standalone")
            .and_then(|value| value.get("dataDir")),
        "standalone.dataDir",
    )?;
    reject_protected_change(
        current.get("caddy").and_then(|value| value.get("install")),
        object.get("caddy").and_then(|value| value.get("install")),
        "caddy.install",
    )?;
    Ok(())
}

fn reject_protected_change(
    current: Option<&Value>,
    proposed: Option<&Value>,
    field: &str,
) -> Result<()> {
    if current == proposed {
        return Ok(());
    }

    Err(AppError::BadRequest(format!(
        "{} is managed by the local installer and cannot be changed from the web workspace",
        field
    )))
}

fn read_json_file(path: &str) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(|error| {
        AppError::InternalServerError(format!("Failed to read {}: {}", path, error))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        AppError::InternalServerError(format!("Failed to parse {}: {}", path, error))
    })
}

fn write_json_file(path: &str, value: &Value) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::InternalServerError(format!(
                "Failed to create {}: {}",
                parent.display(),
                error
            ))
        })?;
    }
    fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(value).map_err(|error| {
                AppError::InternalServerError(format!(
                    "Failed to serialize managed config: {}",
                    error
                ))
            })?
        ),
    )
    .map_err(|error| {
        AppError::InternalServerError(format!("Failed to write {}: {}", path, error))
    })?;
    Ok(())
}
