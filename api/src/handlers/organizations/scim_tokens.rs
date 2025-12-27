use crate::error::{AppError, Result};
use crate::middleware::{check_org_admin, AuthUser};
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, scim_tokens::ScimTokenStore, DB};
use crate::services::tier_enforcement::TierService;
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    // Find organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is admin or owner of organization
    check_org_admin(&state.db, &auth_user.user.id, &org.id).await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_scim,
        "SCIM Provisioning",
    )
    .await?;

    // Generate SCIM token
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

    // Create SCIM token in database
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
    // Find organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is admin or owner of organization
    check_org_admin(&state.db, &auth_user.user.id, &org.id).await?;

    // List tokens
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
    // Find organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is admin or owner of organization
    check_org_admin(&state.db, &auth_user.user.id, &org.id).await?;

    // Revoke token
    ScimTokenStore::revoke(DB::Conn(&state.db), &token_id).await?;

    Ok(Json(()))
}

/// Delete a SCIM token
pub async fn delete_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, token_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    // Find organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify user is admin or owner of organization
    check_org_admin(&state.db, &auth_user.user.id, &org.id).await?;

    // Delete token
    ScimTokenStore::delete(DB::Conn(&state.db), &token_id).await?;

    Ok(Json(()))
}
