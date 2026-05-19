//! BYOP (Bring Your Own Payment) billing credentials handlers
//!
//! Allows organizations to configure their own billing provider credentials
//! to charge their end-users directly.

use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore,
    organization_billing_credentials::OrganizationBillingCredentialsStore,
    organizations::OrganizationStore, DB,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

/// Request for setting billing credentials
#[derive(Debug, Deserialize)]
pub struct SetBillingCredentialsRequest {
    pub api_key: String,
    pub webhook_secret: String,
    pub mode: String, // "test" or "live"
}

/// Response for billing credentials status
#[derive(Debug, Serialize)]
pub struct BillingCredentialsStatusResponse {
    pub configured: bool,
    pub provider: String,
    pub mode: Option<String>,
    pub enabled: bool,
}

/// GET /api/organizations/:org_slug/billing-credentials/:provider
/// Get billing credentials status for a provider
pub async fn get_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<BillingCredentialsStatusResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is owner of the organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

    if membership.role != "owner" {
        return Err(AppError::Forbidden(
            "Only organization owners can view billing credentials".to_string(),
        ));
    }

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Get credentials status
    let status =
        OrganizationBillingCredentialsStore::get_status(DB::Conn(&state.db), &org.id, &provider)
            .await?;

    match status {
        Some(s) => Ok(Json(BillingCredentialsStatusResponse {
            configured: s.configured,
            provider: s.provider,
            mode: Some(s.mode),
            enabled: s.enabled,
        })),
        None => Ok(Json(BillingCredentialsStatusResponse {
            configured: false,
            provider,
            mode: None,
            enabled: false,
        })),
    }
}

/// POST /api/organizations/:org_slug/billing-credentials/:provider
/// Set billing credentials for a provider
pub async fn set_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
    Json(req): Json<SetBillingCredentialsRequest>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is owner of the organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

    if membership.role != "owner" {
        return Err(AppError::Forbidden(
            "Only organization owners can configure billing credentials".to_string(),
        ));
    }

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Validate mode
    if req.mode != "test" && req.mode != "live" {
        return Err(AppError::BadRequest(
            "Invalid mode. Must be test or live".to_string(),
        ));
    }

    // Get encryption service
    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Encryption service unavailable: {}", e))
    })?;

    // Encrypt API key
    let api_key_encrypted = encryption
        .encrypt(&req.api_key)
        .map_err(|e| AppError::InternalServerError(format!("Failed to encrypt API key: {}", e)))?;

    // Encrypt webhook secret
    let webhook_secret_encrypted = encryption.encrypt(&req.webhook_secret).map_err(|e| {
        AppError::InternalServerError(format!("Failed to encrypt webhook secret: {}", e))
    })?;

    let encryption_key_id = encryption.key_id().to_string();

    // Upsert credentials
    OrganizationBillingCredentialsStore::upsert(
        DB::Conn(&state.db),
        &org.id,
        &provider,
        &req.mode,
        api_key_encrypted,
        webhook_secret_encrypted,
        &encryption_key_id,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": format!("Billing credentials for {} ({} mode) configured successfully", provider, req.mode)
    })))
}

/// DELETE /api/organizations/:org_slug/billing-credentials/:provider
/// Delete billing credentials for a provider
pub async fn delete_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is owner of the organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

    if membership.role != "owner" {
        return Err(AppError::Forbidden(
            "Only organization owners can delete billing credentials".to_string(),
        ));
    }

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Delete credentials
    let deleted =
        OrganizationBillingCredentialsStore::delete(DB::Conn(&state.db), &org.id, &provider)
            .await?;

    if deleted == 0 {
        return Err(AppError::NotFound(
            "No billing credentials found for this provider".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({
        "message": format!("Billing credentials for {} deleted successfully", provider),
        "deleted_count": deleted
    })))
}
