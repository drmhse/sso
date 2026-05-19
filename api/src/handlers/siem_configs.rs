//! SIEM Configuration Handlers
//!
//! Endpoints for managing SIEM (Security Information and Event Management) integrations.

use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::services::tier_enforcement::TierService;
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, siem_configs::SiemConfigStore, DB};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct CreateSiemConfigRequest {
    pub name: String,
    pub provider_type: String, // 'Datadog', 'Splunk', 'Elastic', 'Custom'
    pub endpoint_url: String,
    pub api_key: Option<String>,
    pub auth_header: Option<String>,
    pub batch_size: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSiemConfigRequest {
    pub name: Option<String>,
    pub endpoint_url: Option<String>,
    pub api_key: Option<Option<String>>,
    pub auth_header: Option<Option<String>>,
    pub batch_size: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SiemConfigResponse {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub provider_type: String,
    pub endpoint_url: String,
    pub batch_size: i32,
    pub enabled: bool,
    pub last_successful_batch_at: Option<String>,
    pub failure_count: i32,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListSiemConfigsResponse {
    pub siem_configs: Vec<SiemConfigResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
}

/// Check if user can manage SIEM configurations.
async fn can_manage_siem(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    PermissionService::check(
        DB::Conn(&state.db),
        org_id,
        user_id,
        CAP_INTEGRATIONS_MANAGE,
    )
    .await
}

/// Convert database model to API response
fn to_response(model: crate::entities::siem_configs::Model) -> SiemConfigResponse {
    SiemConfigResponse {
        id: model.id,
        org_id: model.org_id,
        name: model.name,
        provider_type: model.provider,
        endpoint_url: model.endpoint_url,
        batch_size: model.batch_size.parse().unwrap_or(100),
        enabled: model.enabled,
        last_successful_batch_at: model
            .last_successful_batch_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        failure_count: model.failure_count,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(model.created_at, Utc).to_rfc3339(),
    }
}

fn decode_siem_secret(
    encryption: &crate::encryption::EncryptionService,
    value: &str,
    field_name: &str,
) -> String {
    let encrypted = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::debug!(
                field = field_name,
                "SIEM secret is stored as plaintext; using legacy fallback"
            );
            return value.to_string();
        }
    };

    match encryption.decrypt(&encrypted) {
        Ok(decrypted) => decrypted,
        Err(error) => {
            tracing::warn!(
                field = field_name,
                error = %error,
                "SIEM secret could not be decrypted; using legacy plaintext fallback"
            );
            value.to_string()
        }
    }
}

/// Create SIEM configuration
pub async fn create_siem_config(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateSiemConfigRequest>,
) -> Result<(StatusCode, Json<SiemConfigResponse>)> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to manage SIEM configurations".to_string(),
        ));
    }

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_siem,
        "Log Streaming (SIEM)",
    )
    .await?;

    // Validate provider type
    let valid_providers = ["Datadog", "Splunk", "Elastic", "Custom"];
    if !valid_providers.contains(&req.provider_type.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid provider type. Must be one of: {}",
            valid_providers.join(", ")
        )));
    }

    // Validate name
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Configuration name cannot be empty".to_string(),
        ));
    }

    // Validate endpoint URL
    if req.endpoint_url.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Endpoint URL cannot be empty".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let user_id = auth_user.user.id.clone();
    let name = req.name.clone();
    let provider_type = req.provider_type.clone();

    // Encrypt sensitive fields if encryption service is available
    let mut api_key = req.api_key.clone();
    let mut auth_header = req.auth_header.clone();

    if let Some(encryption) = &state.encryption {
        if let Some(key) = &api_key {
            let encrypted = encryption.encrypt(key).map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt SIEM API key: {}", e))
            })?;
            api_key = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            ));
        }

        if let Some(header) = &auth_header {
            let encrypted = encryption.encrypt(header).map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt SIEM auth header: {}", e))
            })?;
            auth_header = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            ));
        }
    }

    // Execute transaction with automatic retry on database contention
    let config_id = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_siem_config",
        |db| {
            let org_id = org_id.clone();
            let name = name.clone();
            let provider_type = provider_type.clone();
            let endpoint_url = req.endpoint_url.clone();
            let api_key = api_key.clone();
            let auth_header = auth_header.clone();
            let batch_size = req.batch_size;
            Box::pin(async move {
                let config_id = SiemConfigStore::create(
                    db.clone(),
                    &org_id,
                    &name,
                    &provider_type,
                    &endpoint_url,
                    api_key,
                    auth_header,
                    batch_size,
                )
                .await?;

                Ok(config_id)
            })
        },
    )
    .await?;

    // Non-blocking audit via actor
    let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "siem_config.created")
        .target("siem_config", &config_id)
        .success(true)
        .details_json(Some(json!({
            "siem_config_id": config_id,
            "name": name,
            "provider_type": provider_type
        })))
        .build();
    state.audit_actor.log_org(event).await;

    // Fetch the created config
    let config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| {
            AppError::InternalServerError("Failed to retrieve created config".to_string())
        })?;

    Ok((StatusCode::CREATED, Json(to_response(config))))
}

/// List SIEM configurations for an organization
pub async fn list_siem_configs(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<ListSiemConfigsResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view SIEM configurations".to_string(),
        ));
    }

    let configs = SiemConfigStore::list_by_org(&state.db, &org.id).await?;
    let total = configs.len();

    let response_configs: Vec<SiemConfigResponse> = configs.into_iter().map(to_response).collect();

    Ok(Json(ListSiemConfigsResponse {
        siem_configs: response_configs,
        total,
    }))
}

/// Get a single SIEM configuration
pub async fn get_siem_config(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<SiemConfigResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view SIEM configuration".to_string(),
        ));
    }

    let config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    // Verify the config belongs to this organization
    if config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    Ok(Json(to_response(config)))
}

/// Update SIEM configuration
pub async fn update_siem_config(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdateSiemConfigRequest>,
) -> Result<Json<SiemConfigResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to update SIEM configuration".to_string(),
        ));
    }

    // Verify the config exists and belongs to this organization
    let existing_config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    if existing_config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let user_id = auth_user.user.id.clone();

    // Encrypt sensitive fields if encryption service is available
    let mut api_key = req.api_key.clone();
    let mut auth_header = req.auth_header.clone();

    if let Some(encryption) = &state.encryption {
        if let Some(Some(key)) = &api_key {
            let encrypted = encryption.encrypt(key).map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt SIEM API key: {}", e))
            })?;
            api_key = Some(Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            )));
        }

        if let Some(Some(header)) = &auth_header {
            let encrypted = encryption.encrypt(header).map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt SIEM auth header: {}", e))
            })?;
            auth_header = Some(Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            )));
        }
    }

    // Execute transaction with automatic retry on database contention
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_siem_config",
        |db| {
            let config_id = config_id.clone();
            let name = req.name.clone();
            let endpoint_url = req.endpoint_url.clone();
            let api_key = api_key.clone();
            let auth_header = auth_header.clone();
            let batch_size = req.batch_size;
            let enabled = req.enabled;
            Box::pin(async move {
                SiemConfigStore::update(
                    db.clone(),
                    &config_id,
                    name,
                    endpoint_url,
                    api_key,
                    auth_header,
                    batch_size,
                    enabled,
                )
                .await?;

                Ok(())
            })
        },
    )
    .await?;

    // Non-blocking audit via actor
    let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "siem_config.updated")
        .target("siem_config", &config_id)
        .success(true)
        .details_json(Some(json!({"siem_config_id": config_id})))
        .build();
    state.audit_actor.log_org(event).await;

    // Fetch the updated config
    let config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| {
            AppError::InternalServerError("Failed to retrieve updated config".to_string())
        })?;

    Ok(Json(to_response(config)))
}

/// Delete SIEM configuration
pub async fn delete_siem_config(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to delete SIEM configuration".to_string(),
        ));
    }

    // Verify the config exists and belongs to this organization
    let existing_config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    if existing_config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let user_id = auth_user.user.id.clone();

    // Execute transaction with automatic retry on database contention
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_siem_config",
        |db| {
            let config_id = config_id.clone();
            Box::pin(async move {
                SiemConfigStore::delete(db.clone(), &config_id).await?;
                Ok(())
            })
        },
    )
    .await?;

    // Non-blocking audit via actor
    let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "siem_config.deleted")
        .target("siem_config", &config_id)
        .success(true)
        .details_json(Some(json!({"siem_config_id": config_id})))
        .build();
    state.audit_actor.log_org(event).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Test SIEM connection
pub async fn test_siem_connection(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<TestConnectionResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to test SIEM configuration".to_string(),
        ));
    }

    let config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    // Verify the config belongs to this organization
    if config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    // Decrypt sensitive fields if encryption service is available
    let mut api_key = config.api_key.clone();
    let mut auth_header = config.auth_header.clone();

    if let Some(encryption) = &state.encryption {
        if let Some(key_b64) = &api_key {
            api_key = Some(decode_siem_secret(encryption, key_b64, "api_key"));
        }

        if let Some(header_b64) = &auth_header {
            auth_header = Some(decode_siem_secret(encryption, header_b64, "auth_header"));
        }
    }

    let test_payload = json!({
        "test": true,
        "message": "SIEM connection test from SSO platform",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let test_body = serde_json::to_string(&test_payload).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize test payload: {}", e))
    })?;

    let safe_client = crate::services::safe_http::SafeHttpClient::new()?;
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];

    // Add authentication based on provider type
    match config.provider.as_str() {
        "Datadog" => {
            if let Some(key) = &api_key {
                headers.push(("DD-API-KEY".to_string(), key.clone()));
            }
        }
        "Splunk" => {
            if let Some(key) = &api_key {
                headers.push(("Authorization".to_string(), format!("Splunk {}", key)));
            }
        }
        "Elastic" => {
            if let Some(key) = &api_key {
                headers.push(("Authorization".to_string(), format!("ApiKey {}", key)));
            }
        }
        "Custom" => {
            if let Some(header) = &auth_header {
                if let Some((name, value)) = header.split_once(':') {
                    headers.push((name.trim().to_string(), value.trim().to_string()));
                } else {
                    headers.push(("Authorization".to_string(), header.clone()));
                }
            }
        }
        _ => {}
    }

    let response = safe_client
        .post_with_owned_headers(&config.endpoint_url, test_body, headers)
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => Ok(Json(TestConnectionResponse {
            success: true,
            message: format!(
                "Successfully connected to SIEM endpoint (status: {})",
                resp.status()
            ),
        })),
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Ok(Json(TestConnectionResponse {
                success: false,
                message: format!("SIEM endpoint returned error status {}: {}", status, body),
            }))
        }
        Err(e) => Ok(Json(TestConnectionResponse {
            success: false,
            message: format!("Failed to connect to SIEM endpoint: {}", e),
        })),
    }
}
