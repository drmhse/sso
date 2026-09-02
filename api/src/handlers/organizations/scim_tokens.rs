use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::services::tier_enforcement::TierService;
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, scim_tokens::ScimTokenStore};
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

async fn require_integration_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    crate::handlers::organizations::ensure_organization_active(&state.db, org_id).await?;
    if PermissionService::check(
        DB::Conn(&state.db),
        org_id,
        user_id,
        CAP_INTEGRATIONS_MANAGE,
    )
    .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage integrations".to_string(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub name: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub name: String,
    pub token: String,
    pub prefix: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScimTokenResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// Create a new SCIM token for an organization
pub async fn create_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_scim,
        "SCIM Provisioning",
    )
    .await?;

    let (plain_token, prefix, hash) = ScimTokenStore::generate();

    // Parse expires_at if provided
    let expires_at_naive = if let Some(expires_at_str) = &req.expires_at {
        Some(
            DateTime::parse_from_rfc3339(expires_at_str)
                .map_err(|e| AppError::BadRequest(format!("Invalid expires_at format: {}", e)))?
                .naive_utc(),
        )
    } else {
        None
    };

    let token_model = ScimTokenStore::create(
        DB::Conn(&state.db),
        &org.id,
        &req.name,
        &hash,
        &prefix,
        &auth_user.user.id,
        expires_at_naive,
    )
    .await?;

    Ok(Json(CreateScimTokenResponse {
        id: token_model.id,
        name: token_model.name,
        token: plain_token,
        prefix: token_model.prefix,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(token_model.created_at, Utc)
            .to_rfc3339(),
        expires_at: token_model
            .expires_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
    }))
}

/// List SCIM tokens for an organization
pub async fn list_scim_tokens(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<ScimTokenResponse>>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let tokens = ScimTokenStore::list_by_org(DB::Conn(&state.db), &org.id).await?;

    let response = tokens
        .into_iter()
        .map(|token| ScimTokenResponse {
            id: token.id,
            name: token.name,
            prefix: token.prefix,
            active: token.active,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(token.created_at, Utc)
                .to_rfc3339(),
            expires_at: token
                .expires_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
            last_used_at: token
                .last_used_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        })
        .collect();

    Ok(Json(response))
}

/// Revoke a SCIM token
pub async fn revoke_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, token_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    if !ScimTokenStore::revoke_in_org(DB::Conn(&state.db), &org.id, &token_id).await? {
        return Err(AppError::NotFound("SCIM token not found".to_string()));
    }

    Ok(Json(()))
}

/// Delete a SCIM token
pub async fn delete_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, token_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    if !ScimTokenStore::delete_in_org(DB::Conn(&state.db), &org.id, &token_id).await? {
        return Err(AppError::NotFound("SCIM token not found".to_string()));
    }

    Ok(Json(()))
}
