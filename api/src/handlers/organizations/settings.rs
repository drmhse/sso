use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore,
    organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    organizations::OrganizationStore, DB,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

// OAuth Credentials Management

#[derive(Debug, Deserialize)]
pub struct SetOAuthCredentialsRequest {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthCredentialsResponse {
    pub provider: String,
    pub client_id: String,
    pub has_secret: bool,
}

/// Set organization OAuth credentials for a provider
pub async fn set_org_oauth_credentials(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, provider)): Path<(String, String)>,
    Json(req): Json<SetOAuthCredentialsRequest>,
) -> Result<Json<OAuthCredentialsResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is admin or owner of the organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &user.user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

    if membership.role != "owner" && membership.role != "admin" {
        return Err(AppError::Forbidden(
            "Must be an owner or admin to manage OAuth credentials".to_string(),
        ));
    }

    // Validate provider
    if provider != "github" && provider != "google" && provider != "microsoft" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be github, google, or microsoft".to_string(),
        ));
    }

    // Get encryption service
    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Encryption service unavailable: {}", e))
    })?;

    // Encrypt client secret
    let client_secret_encrypted = encryption
        .encrypt(&req.client_secret)
        .map_err(|e| AppError::InternalServerError(format!("Failed to encrypt secret: {}", e)))?;

    let encryption_key_id = encryption.key_id().to_string();

    // Upsert credentials using store layer
    OrganizationOAuthCredentialsStore::upsert(
        DB::Conn(&state.db),
        &org.id,
        &provider,
        &req.client_id,
        client_secret_encrypted,
        &encryption_key_id,
    )
    .await?;

    Ok(Json(OAuthCredentialsResponse {
        provider,
        client_id: req.client_id,
        has_secret: true,
    }))
}

/// Get organization OAuth credentials for a provider (returns client_id only)
pub async fn get_org_oauth_credentials(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<OAuthCredentialsResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is a member of the organization
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &user.user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

    // Validate provider
    if provider != "github" && provider != "google" && provider != "microsoft" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be github, google, or microsoft".to_string(),
        ));
    }

    // Fetch credentials
    let client_id =
        OrganizationOAuthCredentialsStore::find_client_id(DB::Conn(&state.db), &org.id, &provider)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("OAuth credentials not found for this provider".to_string())
            })?;

    Ok(Json(OAuthCredentialsResponse {
        provider,
        client_id,
        has_secret: true,
    }))
}

// SMTP Configuration Management

#[derive(Debug, Deserialize)]
pub struct SetSmtpRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SmtpConfigResponse {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub configured: bool,
}

/// Set SMTP configuration for an organization
pub async fn set_org_smtp(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(org_slug): Path<String>,
    Json(payload): Json<SetSmtpRequest>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin of the organization
    let membership = MembershipStore::find_by_org_and_user(
        DB::Conn(&state.db),
        &organization.id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    if membership.role != "owner" && membership.role != "admin" {
        return Err(AppError::Forbidden(
            "Only owners and admins can configure SMTP".to_string(),
        ));
    }

    // Encrypt the SMTP password
    let encryption = state.encryption.as_ref().ok_or_else(|| {
        AppError::InternalServerError("Encryption service not available".to_string())
    })?;

    let encrypted_password = encryption.encrypt(&payload.password).map_err(|e| {
        tracing::error!("Failed to encrypt SMTP password: {}", e);
        AppError::InternalServerError("Failed to encrypt SMTP password".to_string())
    })?;

    // Update organization SMTP settings
    OrganizationStore::update_smtp_config(
        DB::Conn(&state.db),
        &organization.id,
        &payload.host,
        payload.port as i64,
        &payload.username,
        encrypted_password,
        &payload.from_email,
        payload.from_name.as_deref(),
        Some(encryption.key_id()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": "SMTP configuration saved successfully"
    })))
}

/// Get SMTP configuration for an organization (without password)
pub async fn get_org_smtp(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<SmtpConfigResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member of the organization
    let membership = MembershipStore::find_by_org_and_user(
        DB::Conn(&state.db),
        &organization.id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    if membership.role != "owner" && membership.role != "admin" {
        return Err(AppError::Forbidden(
            "Only owners and admins can view SMTP configuration".to_string(),
        ));
    }

    let configured = organization.smtp_host.is_some();

    Ok(Json(SmtpConfigResponse {
        host: organization.smtp_host.unwrap_or_default(),
        port: organization.smtp_port.map(|p| p as u16).unwrap_or(587),
        username: organization.smtp_username.unwrap_or_default(),
        from_email: organization.smtp_from_email.unwrap_or_default(),
        from_name: organization.smtp_from_name,
        configured,
    }))
}

/// Delete SMTP configuration for an organization (revert to platform-level)
pub async fn delete_org_smtp(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin of the organization
    let membership = MembershipStore::find_by_org_and_user(
        DB::Conn(&state.db),
        &organization.id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    if membership.role != "owner" && membership.role != "admin" {
        return Err(AppError::Forbidden(
            "Only owners and admins can delete SMTP configuration".to_string(),
        ));
    }

    // Clear SMTP settings
    OrganizationStore::clear_smtp_config(DB::Conn(&state.db), &organization.id).await?;

    Ok(Json(serde_json::json!({
        "message": "SMTP configuration deleted successfully. Organization will now use platform-level SMTP."
    })))
}
