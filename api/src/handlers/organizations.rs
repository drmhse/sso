use crate::constants::{
    DEFAULT_MAX_USERS, DEFAULT_TIER_NAME, MAX_NAME_LENGTH, MAX_SLUG_LENGTH, MIN_NAME_LENGTH, MIN_SLUG_LENGTH, RESERVED_SLUGS,
};
use crate::db::models::{Membership, Organization, OrganizationTier, User};
use crate::error::{AppError, Result};
use crate::handlers::auth::AppState;
use crate::middleware::AuthUser;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationPublicRequest {
    pub slug: String,
    pub name: String,
    pub owner_email: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransferOwnershipRequest {
    pub new_owner_email: String,
}

#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub organization: Organization,
    pub membership_count: i64,
    pub service_count: i64,
    pub tier: Option<OrganizationTier>,
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationPublicResponse {
    pub organization: Organization,
    pub owner: User,
    pub membership: Membership,
}

#[derive(Debug, Serialize)]
pub struct OrganizationMember {
    pub user: User,
    pub membership: Membership,
}

#[derive(Debug, Serialize)]
pub struct MemberListResponse {
    pub members: Vec<OrganizationMember>,
    pub total: i64,
    pub limit: LimitInfo,
}

#[derive(Debug, Serialize)]
pub struct LimitInfo {
    pub current: i64,
    pub max: i64,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMembersQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListOrganizationsQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub status: Option<String>,
}

/// Create a new organization (public endpoint - takes owner_email)
pub async fn create_organization_public(
    State(state): State<AppState>,
    Json(req): Json<CreateOrganizationPublicRequest>,
) -> Result<Json<CreateOrganizationPublicResponse>> {
    // Validate input
    validate_organization_slug(&req.slug)?;
    validate_organization_name(&req.name)?;
    validate_email(&req.owner_email)?;

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Check if slug already exists
    let existing = sqlx::query!("SELECT id FROM organizations WHERE slug = ?", req.slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    if existing.is_some() {
        return Err(AppError::BadRequest(
            "Unable to create organization with the provided information".to_string(),
        ));
    }

    // Get free tier
    let free_tier = sqlx::query!("SELECT id FROM organization_tiers WHERE name = ?", DEFAULT_TIER_NAME)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    // Find or create owner user
    let owner = find_or_create_user_tx(&mut tx, &req.owner_email).await?;

    // Create organization
    let org_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let organization = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, slug, name, owner_user_id, status, tier_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
         RETURNING *"
    )
    .bind(&org_id)
    .bind(&req.slug)
    .bind(&req.name)
    .bind(&owner.id)
    .bind(&free_tier.id)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create owner membership
    let membership_id = Uuid::new_v4().to_string();
    let membership = sqlx::query_as::<_, Membership>(
        "INSERT INTO memberships (id, org_id, user_id, role, created_at)
         VALUES (?, ?, ?, 'owner', ?)
         RETURNING *",
    )
    .bind(&membership_id)
    .bind(&org_id)
    .bind(&owner.id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(CreateOrganizationPublicResponse {
        organization,
        owner,
        membership,
    }))
}

/// Helper function to find or create a user (for public org creation)
async fn find_or_create_user_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    email: &str,
) -> Result<User> {
    // Check if user exists
    if let Some(user) = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::Database)?
    {
        return Ok(user);
    }

    // Create new user
    let id = Uuid::new_v4().to_string();
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, email, created_at)
         VALUES (?, ?, ?)
         RETURNING *",
    )
    .bind(&id)
    .bind(email)
    .bind(Utc::now())
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::Database)?;

    Ok(user)
}

/// Get organization by slug
pub async fn get_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<OrganizationResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    crate::middleware::check_org_membership(&state.pool, &user.id, &organization.id, &[]).await?;

    let (membership_count, service_count, tier) =
        get_organization_stats(&state.pool, &organization.id).await?;

    Ok(Json(OrganizationResponse {
        organization,
        membership_count,
        service_count,
        tier,
    }))
}

/// Update organization (owner/admin only)
pub async fn update_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<UpdateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin
    let _membership =
        crate::middleware::check_org_admin(&state.pool, &user.id, &organization.id).await?;

    // Simple update approach
    let now = Utc::now();

    if let Some(name) = &req.name {
        sqlx::query!(
            "UPDATE organizations SET name = ?, updated_at = ? WHERE id = ?",
            name,
            now,
            organization.id
        )
        .execute(&state.pool)
        .await
        .map_err(AppError::Database)?;
    } else {
        // If no fields were updated, just update the timestamp
        sqlx::query!(
            "UPDATE organizations SET updated_at = ? WHERE id = ?",
            now,
            organization.id
        )
        .execute(&state.pool)
        .await
        .map_err(AppError::Database)?;
    }

    // Fetch updated organization
    let updated_org = get_organization_by_id(&state.pool, &organization.id).await?;
    let (membership_count, service_count, tier) =
        get_organization_stats(&state.pool, &organization.id).await?;

    Ok(Json(OrganizationResponse {
        organization: updated_org,
        membership_count,
        service_count,
        tier,
    }))
}

/// List organization members
pub async fn list_members(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(query): Query<ListMembersQuery>,
) -> Result<Json<MemberListResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    crate::middleware::check_org_membership(&state.pool, &user.id, &organization.id, &[]).await?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Use simple query approach to avoid sqlx macro issues
    let members = if let Some(ref role_filter) = query.role {
        sqlx::query("SELECT u.id, u.email, u.is_platform_owner, u.created_at, m.id as membership_id, m.role as membership_role, m.created_at as membership_created_at FROM users u JOIN memberships m ON u.id = m.user_id WHERE m.org_id = ? AND m.role = ? ORDER BY m.created_at ASC LIMIT ? OFFSET ?")
            .bind(&organization.id)
            .bind(role_filter)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Database)?
    } else {
        sqlx::query("SELECT u.id, u.email, u.is_platform_owner, u.created_at, m.id as membership_id, m.role as membership_role, m.created_at as membership_created_at FROM users u JOIN memberships m ON u.id = m.user_id WHERE m.org_id = ? ORDER BY m.created_at ASC LIMIT ? OFFSET ?")
            .bind(&organization.id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Database)?
    };

    let member_responses: Vec<OrganizationMember> = members
        .into_iter()
        .map(|row| {
            let user = crate::db::models::User {
                id: row.get("id"),
                email: row.get("email"),
                is_platform_owner: row.get("is_platform_owner"),
                created_at: row.get("created_at"),
            };
            let membership = crate::db::models::Membership {
                id: row.get("membership_id"),
                org_id: organization.id.clone(),
                user_id: user.id.clone(),
                role: row.get("membership_role"),
                created_at: row.get("membership_created_at"),
            };
            OrganizationMember { user, membership }
        })
        .collect();

    // Get total member count
    let total_members: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM memberships WHERE org_id = ?")
            .bind(&organization.id)
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Database)?;

    // Get organization limits
    let (max_users, limit_source) = if let Some(custom_limit) = organization.max_users {
        (custom_limit, "custom".to_string())
    } else {
        // Get tier default
        let tier = sqlx::query_as::<_, OrganizationTier>(
            "SELECT t.* FROM organization_tiers t
             JOIN organizations o ON o.tier_id = t.id
             WHERE o.id = ?",
        )
        .bind(&organization.id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?;

        if let Some(tier) = tier {
            (tier.default_max_users, tier.name)
        } else {
            (DEFAULT_MAX_USERS, DEFAULT_TIER_NAME.to_string()) // Default free tier
        }
    };

    Ok(Json(MemberListResponse {
        members: member_responses,
        total: total_members,
        limit: LimitInfo {
            current: total_members,
            max: max_users,
            source: limit_source,
        },
    }))
}

/// Update member role (owner only)
pub async fn update_member_role(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRoleRequest>,
) -> Result<Json<OrganizationMember>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner
    crate::middleware::check_org_owner(&state.pool, &user.id, &organization.id).await?;

    // Validate role
    if !crate::constants::VALID_ORG_ROLES.contains(&req.role.as_str()) {
        return Err(AppError::BadRequest(
            "Invalid role. Must be owner, admin, or member".to_string(),
        ));
    }

    // Cannot change own role (prevent self-demotion from owner)
    if user_id == user.id {
        return Err(AppError::BadRequest(
            "Cannot change your own role".to_string(),
        ));
    }

    // Get target membership
    let membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&organization.id)
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("User is not a member of this organization".to_string()))?;

    // Update role
    sqlx::query!(
        "UPDATE memberships SET role = ? WHERE id = ?",
        req.role,
        membership.id
    )
    .execute(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // If setting new owner, update organization and previous owner
    if req.role == "owner" {
        let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

        // Update organization owner
        sqlx::query!(
            "UPDATE organizations SET owner_user_id = ? WHERE id = ?",
            user_id,
            organization.id
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        // Demote previous owner to admin
        sqlx::query!(
            "UPDATE memberships SET role = 'admin' WHERE org_id = ? AND user_id = ?",
            organization.id,
            user.id
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        tx.commit().await.map_err(AppError::Database)?;
    }

    // Fetch updated member
    let target_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?;

    let updated_membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&organization.id)
    .bind(&user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(OrganizationMember {
        user: target_user,
        membership: updated_membership,
    }))
}

/// Remove member from organization (owner/admin only)
pub async fn remove_member(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin (owner can remove anyone, admin can remove members)
    let caller_membership =
        crate::middleware::check_org_admin(&state.pool, &user.id, &organization.id).await?;

    // Cannot remove yourself
    if user_id == user.id {
        return Err(AppError::BadRequest(
            "Cannot remove yourself from the organization".to_string(),
        ));
    }

    // Get target membership
    let target_membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&organization.id)
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("User is not a member of this organization".to_string()))?;

    // Check permissions: owner can remove anyone, admin can only remove members, not owners/admins
    if caller_membership.role != "owner" && (target_membership.role == "owner" || target_membership.role == "admin") {
        return Err(AppError::Forbidden(
            "Only owners can remove other owners and admins".to_string(),
        ));
    }

    // Remove membership
    sqlx::query!("DELETE FROM memberships WHERE id = ?", target_membership.id)
        .execute(&state.pool)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(()))
}

/// Transfer ownership to another member (owner only)
pub async fn transfer_ownership(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<Json<OrganizationMember>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner
    crate::middleware::check_org_owner(&state.pool, &user.id, &organization.id).await?;

    // Find new owner by email
    let new_owner = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&req.new_owner_email)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User with that email not found".to_string()))?;

    // Check if new owner is a member
    let membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&organization.id)
    .bind(&new_owner.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("User is not a member of this organization".to_string()))?;

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Update organization owner
    sqlx::query!(
        "UPDATE organizations SET owner_user_id = ? WHERE id = ?",
        new_owner.id,
        organization.id
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Update membership roles
    sqlx::query!(
        "UPDATE memberships SET role = 'owner' WHERE id = ?",
        membership.id
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    sqlx::query!(
        "UPDATE memberships SET role = 'admin' WHERE org_id = ? AND user_id = ?",
        organization.id,
        user.id
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    // Fetch updated membership
    let updated_membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&organization.id)
    .bind(&new_owner.id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(OrganizationMember {
        user: new_owner,
        membership: updated_membership,
    }))
}

/// List user's organizations
pub async fn list_user_organizations(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Query(query): Query<ListOrganizationsQuery>,
) -> Result<Json<Vec<OrganizationResponse>>> {
    let user = &auth_user.user;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Build simple query with optional status filter
    let organizations = if let Some(status) = &query.status {
        sqlx::query_as::<_, Organization>(
            "SELECT o.* FROM organizations o
             JOIN memberships m ON o.id = m.org_id
             WHERE m.user_id = ? AND o.status = ?
             ORDER BY m.created_at ASC LIMIT ? OFFSET ?",
        )
        .bind(&user.id)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Database)?
    } else {
        sqlx::query_as::<_, Organization>(
            "SELECT o.* FROM organizations o
             JOIN memberships m ON o.id = m.org_id
             WHERE m.user_id = ?
             ORDER BY m.created_at ASC LIMIT ? OFFSET ?",
        )
        .bind(&user.id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Database)?
    };

    let mut results = Vec::new();
    for org in organizations {
        let (membership_count, service_count, tier) =
            get_organization_stats(&state.pool, &org.id).await?;
        results.push(OrganizationResponse {
            organization: org,
            membership_count,
            service_count,
            tier,
        });
    }

    Ok(Json(results))
}

// Helper functions

async fn get_organization_by_id(pool: &SqlitePool, org_id: &str) -> Result<Organization> {
    sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(org_id)
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)
}

async fn get_organization_stats(
    pool: &SqlitePool,
    org_id: &str,
) -> Result<(i64, i64, Option<OrganizationTier>)> {
    let membership_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM memberships WHERE org_id = ?")
            .bind(org_id)
            .fetch_one(pool)
            .await
            .map_err(AppError::Database)?;

    let service_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM services WHERE org_id = ?")
        .bind(org_id)
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)?;

    let tier = sqlx::query_as::<_, OrganizationTier>(
        "SELECT t.* FROM organization_tiers t
         JOIN organizations o ON o.tier_id = t.id
         WHERE o.id = ?",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    Ok((membership_count, service_count, tier))
}

pub async fn ensure_organization_active(pool: &SqlitePool, org_id: &str) -> Result<Organization> {
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(org_id)
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)?;

    if org.status != "active" {
        return Err(AppError::Forbidden(format!(
            "Organization is not active. Current status: {}",
            org.status
        )));
    }

    Ok(org)
}

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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_one(&state.pool)
        .await?;

    // Verify user is admin or owner of the organization
    let membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&user.user.id)
    .fetch_one(&state.pool)
    .await?;

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

    // Upsert credentials
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO organization_oauth_credentials (id, org_id, provider, client_id, client_secret_encrypted, encryption_key_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
         ON CONFLICT(org_id, provider) DO UPDATE SET
            client_id = excluded.client_id,
            client_secret_encrypted = excluded.client_secret_encrypted,
            encryption_key_id = excluded.encryption_key_id,
            updated_at = datetime('now')"
    )
    .bind(&id)
    .bind(&org.id)
    .bind(&provider)
    .bind(&req.client_id)
    .bind(&client_secret_encrypted)
    .bind(&encryption_key_id)
    .execute(&state.pool)
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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_one(&state.pool)
        .await?;

    // Verify user is a member of the organization
    let _membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&user.user.id)
    .fetch_one(&state.pool)
    .await?;

    // Validate provider
    if provider != "github" && provider != "google" && provider != "microsoft" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be github, google, or microsoft".to_string(),
        ));
    }

    // Fetch credentials
    let creds = sqlx::query!(
        "SELECT client_id FROM organization_oauth_credentials WHERE org_id = ? AND provider = ?",
        org.id,
        provider
    )
    .fetch_optional(&state.pool)
    .await?;

    if let Some(creds) = creds {
        Ok(Json(OAuthCredentialsResponse {
            provider,
            client_id: creds.client_id,
            has_secret: true,
        }))
    } else {
        Err(AppError::NotFound(
            "OAuth credentials not found for this provider".to_string(),
        ))
    }
}

// Validation helper functions

fn validate_organization_slug(slug: &str) -> Result<()> {
    if slug.len() < MIN_SLUG_LENGTH || slug.len() > MAX_SLUG_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Slug must be between {} and {} characters",
            MIN_SLUG_LENGTH, MAX_SLUG_LENGTH
        )));
    }

    if !slug
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "Slug can only contain alphanumeric characters, hyphens, and underscores".to_string(),
        ));
    }

    // Check for reserved slugs
    if RESERVED_SLUGS.contains(&slug) {
        return Err(AppError::BadRequest("Slug is reserved".to_string()));
    }

    Ok(())
}

fn validate_organization_name(name: &str) -> Result<()> {
    if name.len() < MIN_NAME_LENGTH || name.len() > MAX_NAME_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Name must be between {} and {} characters",
            MIN_NAME_LENGTH, MAX_NAME_LENGTH
        )));
    }

    if name.trim().is_empty() {
        return Err(AppError::BadRequest("Name cannot be empty".to_string()));
    }

    Ok(())
}

fn validate_email(email: &str) -> Result<()> {
    if !email.contains('@') || email.len() < 5 {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    Ok(())
}

// ============================================================================
// END-USER MANAGEMENT
// Manage organization's customers (end-users who have subscriptions)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListEndUsersQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub service_slug: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EndUserSubscription {
    pub service_id: String,
    pub service_slug: String,
    pub service_name: String,
    pub plan_id: String,
    pub plan_name: String,
    pub status: String,
    pub current_period_end: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EndUserIdentity {
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EndUser {
    pub user: User,
    pub subscriptions: Vec<EndUserSubscription>,
    pub identities: Vec<EndUserIdentity>,
}

#[derive(Debug, Serialize)]
pub struct EndUserListResponse {
    pub users: Vec<EndUser>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct EndUserDetailResponse {
    pub user: User,
    pub subscriptions: Vec<EndUserSubscription>,
    pub identities: Vec<EndUserIdentity>,
    pub session_count: i64,
}

/// List all end-users for an organization
/// End-users are those who have subscriptions to the organization's services
pub async fn list_end_users(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(query): Query<ListEndUsersQuery>,
) -> Result<Json<EndUserListResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member (any role can view end-users)
    crate::middleware::check_org_membership(&state.pool, &user.id, &organization.id, &[]).await?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Build query to get users who have identities or subscriptions for this organization
    // This includes users who logged in (have identities) even if they don't have subscriptions yet
    let (users_query, service_id) = if let Some(ref service_slug) = query.service_slug {
        // Filter by specific service
        let service = sqlx::query_as::<_, crate::db::models::Service>(
            "SELECT * FROM services WHERE slug = ? AND org_id = ?",
        )
        .bind(service_slug)
        .bind(&organization.id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound(format!("Service '{}' not found", service_slug)))?;

        (
            "SELECT DISTINCT u.id, u.email, u.is_platform_owner, u.created_at
             FROM users u
             LEFT JOIN identities i ON u.id = i.user_id AND i.issuing_org_id = ? AND i.issuing_service_id = ?
             LEFT JOIN subscriptions sub ON u.id = sub.user_id AND sub.service_id = ?
             WHERE (i.user_id IS NOT NULL OR sub.user_id IS NOT NULL)
             ORDER BY u.created_at DESC
             LIMIT ? OFFSET ?".to_string(),
            Some(service.id.clone())
        )
    } else {
        // Show all users across all services in the organization
        (
            "SELECT DISTINCT u.id, u.email, u.is_platform_owner, u.created_at
             FROM users u
             LEFT JOIN identities i ON u.id = i.user_id AND i.issuing_org_id = ?
             LEFT JOIN subscriptions sub ON u.id = sub.user_id
             LEFT JOIN services s ON sub.service_id = s.id AND s.org_id = ?
             WHERE (i.user_id IS NOT NULL OR (sub.user_id IS NOT NULL AND s.org_id IS NOT NULL))
             ORDER BY u.created_at DESC
             LIMIT ? OFFSET ?".to_string(),
            None
        )
    };

    let end_user_rows = if let Some(ref svc_id) = service_id {
        sqlx::query(&users_query)
            .bind(&organization.id)
            .bind(svc_id)
            .bind(svc_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Database)?
    } else {
        sqlx::query(&users_query)
            .bind(&organization.id)
            .bind(&organization.id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Database)?
    };

    // Build user objects and collect their IDs
    let users: Vec<User> = end_user_rows
        .iter()
        .map(|row| User {
            id: row.get("id"),
            email: row.get("email"),
            is_platform_owner: row.get("is_platform_owner"),
            created_at: row.get("created_at"),
        })
        .collect();

    let user_ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();

    // Early return if no users found
    if user_ids.is_empty() {
        return Ok(Json(EndUserListResponse {
            users: Vec::new(),
            total: 0,
            page,
            limit,
        }));
    }

    // Build placeholders for IN clause (?, ?, ?, ...)
    let placeholders = user_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");

    // Fetch subscriptions for these users (optionally filtered by service)
    let subscription_query = if service_id.is_some() {
        format!(
            "SELECT sub.user_id, sub.service_id, s.slug as service_slug, s.name as service_name,
                    sub.plan_id, p.name as plan_name, sub.status,
                    sub.current_period_end, sub.created_at as subscription_created_at
             FROM subscriptions sub
             INNER JOIN services s ON sub.service_id = s.id
             INNER JOIN plans p ON sub.plan_id = p.id
             WHERE sub.user_id IN ({}) AND sub.service_id = ?
             ORDER BY sub.created_at DESC",
            placeholders
        )
    } else {
        format!(
            "SELECT sub.user_id, sub.service_id, s.slug as service_slug, s.name as service_name,
                    sub.plan_id, p.name as plan_name, sub.status,
                    sub.current_period_end, sub.created_at as subscription_created_at
             FROM subscriptions sub
             INNER JOIN services s ON sub.service_id = s.id
             INNER JOIN plans p ON sub.plan_id = p.id
             WHERE sub.user_id IN ({}) AND s.org_id = ?
             ORDER BY sub.created_at DESC",
            placeholders
        )
    };

    let mut subscription_query_builder = sqlx::query(&subscription_query);
    for user_id in &user_ids {
        subscription_query_builder = subscription_query_builder.bind(user_id);
    }
    if let Some(ref svc_id) = service_id {
        subscription_query_builder = subscription_query_builder.bind(svc_id);
    } else {
        subscription_query_builder = subscription_query_builder.bind(&organization.id);
    }

    let all_subscription_rows = subscription_query_builder
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Database)?;

    // Group subscriptions by user_id
    let mut subscriptions_by_user: HashMap<String, Vec<EndUserSubscription>> = HashMap::new();
    for sub_row in all_subscription_rows {
        let user_id: String = sub_row.get("user_id");
        let subscription = EndUserSubscription {
            service_id: sub_row.get("service_id"),
            service_slug: sub_row.get("service_slug"),
            service_name: sub_row.get("service_name"),
            plan_id: sub_row.get("plan_id"),
            plan_name: sub_row.get("plan_name"),
            status: sub_row.get("status"),
            current_period_end: sub_row.get("current_period_end"),
            created_at: sub_row.get("subscription_created_at"),
        };
        subscriptions_by_user
            .entry(user_id)
            .or_default()
            .push(subscription);
    }

    // Fetch identities for these users (optionally filtered by service)
    let identity_query = if service_id.is_some() {
        format!(
            "SELECT user_id, provider, provider_user_id, created_at
             FROM identities
             WHERE user_id IN ({}) AND issuing_org_id = ? AND issuing_service_id = ?
             ORDER BY created_at ASC",
            placeholders
        )
    } else {
        format!(
            "SELECT user_id, provider, provider_user_id, created_at
             FROM identities
             WHERE user_id IN ({}) AND issuing_org_id = ?
             ORDER BY created_at ASC",
            placeholders
        )
    };

    let mut identity_query_builder = sqlx::query(&identity_query);
    for user_id in &user_ids {
        identity_query_builder = identity_query_builder.bind(user_id);
    }
    identity_query_builder = identity_query_builder.bind(&organization.id);
    if let Some(ref svc_id) = service_id {
        identity_query_builder = identity_query_builder.bind(svc_id);
    }

    let all_identity_rows = identity_query_builder
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Database)?;

    // Group identities by user_id
    let mut identities_by_user: HashMap<String, Vec<EndUserIdentity>> = HashMap::new();
    for id_row in all_identity_rows {
        let user_id: String = id_row.get("user_id");
        let identity = EndUserIdentity {
            provider: id_row.get("provider"),
            provider_user_id: id_row.get("provider_user_id"),
            created_at: id_row.get("created_at"),
        };
        identities_by_user
            .entry(user_id)
            .or_default()
            .push(identity);
    }

    // Build end-user objects using the grouped data
    let end_users: Vec<EndUser> = users
        .into_iter()
        .map(|user| {
            let subscriptions = subscriptions_by_user
                .remove(&user.id)
                .unwrap_or_default();
            let identities = identities_by_user.remove(&user.id).unwrap_or_default();

            EndUser {
                user,
                subscriptions,
                identities,
            }
        })
        .collect();

    // Get total count (matching the filter logic above)
    let total: i64 = if let Some(ref svc_id) = service_id {
        sqlx::query_scalar(
            "SELECT COUNT(DISTINCT u.id)
             FROM users u
             LEFT JOIN identities i ON u.id = i.user_id AND i.issuing_org_id = ? AND i.issuing_service_id = ?
             LEFT JOIN subscriptions sub ON u.id = sub.user_id AND sub.service_id = ?
             WHERE (i.user_id IS NOT NULL OR sub.user_id IS NOT NULL)",
        )
        .bind(&organization.id)
        .bind(svc_id)
        .bind(svc_id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(DISTINCT u.id)
             FROM users u
             LEFT JOIN identities i ON u.id = i.user_id AND i.issuing_org_id = ?
             LEFT JOIN subscriptions sub ON u.id = sub.user_id
             LEFT JOIN services s ON sub.service_id = s.id AND s.org_id = ?
             WHERE (i.user_id IS NOT NULL OR (sub.user_id IS NOT NULL AND s.org_id IS NOT NULL))",
        )
        .bind(&organization.id)
        .bind(&organization.id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?
    };

    Ok(Json(EndUserListResponse {
        users: end_users,
        total,
        page,
        limit,
    }))
}

/// Get detailed information about a specific end-user
pub async fn get_end_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, end_user_id)): Path<(String, String)>,
) -> Result<Json<EndUserDetailResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member (any role can view end-users)
    crate::middleware::check_org_membership(&state.pool, &user.id, &organization.id, &[]).await?;

    // Get end-user
    let end_user_obj = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&end_user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("End-user not found".to_string()))?;

    // Verify this user has subscriptions to this organization's services
    let subscription_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM subscriptions sub
         INNER JOIN services s ON sub.service_id = s.id
         WHERE sub.user_id = ? AND s.org_id = ?",
    )
    .bind(&end_user_id)
    .bind(&organization.id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    if subscription_count == 0 {
        return Err(AppError::NotFound(
            "User is not an end-user of this organization".to_string(),
        ));
    }

    // Get subscriptions
    let subscription_rows = sqlx::query(
        "SELECT sub.service_id, s.slug as service_slug, s.name as service_name,
                sub.plan_id, p.name as plan_name, sub.status,
                sub.current_period_end, sub.created_at as subscription_created_at
         FROM subscriptions sub
         INNER JOIN services s ON sub.service_id = s.id
         INNER JOIN plans p ON sub.plan_id = p.id
         WHERE sub.user_id = ? AND s.org_id = ?
         ORDER BY sub.created_at DESC",
    )
    .bind(&end_user_id)
    .bind(&organization.id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let subscriptions: Vec<EndUserSubscription> = subscription_rows
        .into_iter()
        .map(|sub_row| EndUserSubscription {
            service_id: sub_row.get("service_id"),
            service_slug: sub_row.get("service_slug"),
            service_name: sub_row.get("service_name"),
            plan_id: sub_row.get("plan_id"),
            plan_name: sub_row.get("plan_name"),
            status: sub_row.get("status"),
            current_period_end: sub_row.get("current_period_end"),
            created_at: sub_row.get("subscription_created_at"),
        })
        .collect();

    // Get identities that were created via this organization's services
    // Only show identities where issuing_org_id matches this organization
    let identity_rows = sqlx::query(
        "SELECT provider, provider_user_id, created_at
         FROM identities
         WHERE user_id = ? AND issuing_org_id = ?
         ORDER BY created_at ASC",
    )
    .bind(&end_user_id)
    .bind(&organization.id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let identities: Vec<EndUserIdentity> = identity_rows
        .into_iter()
        .map(|id_row| EndUserIdentity {
            provider: id_row.get("provider"),
            provider_user_id: id_row.get("provider_user_id"),
            created_at: id_row.get("created_at"),
        })
        .collect();

    // Get active session count
    let session_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM sessions
         WHERE user_id = ? AND expires_at > datetime('now')",
    )
    .bind(&end_user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(EndUserDetailResponse {
        user: end_user_obj,
        subscriptions,
        identities,
        session_count,
    }))
}

/// Revoke all active sessions for an end-user (admin/owner only)
pub async fn revoke_end_user_sessions(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, end_user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let user = &auth_user.user;

    // Find organization
    let organization =
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
            .bind(&org_slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is admin or owner (required for session management)
    crate::middleware::check_org_admin(&state.pool, &user.id, &organization.id).await?;

    // Verify this user has subscriptions to this organization's services
    let subscription_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM subscriptions sub
         INNER JOIN services s ON sub.service_id = s.id
         WHERE sub.user_id = ? AND s.org_id = ?",
    )
    .bind(&end_user_id)
    .bind(&organization.id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    if subscription_count == 0 {
        return Err(AppError::NotFound(
            "User is not an end-user of this organization".to_string(),
        ));
    }

    // Delete all active sessions for this user
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(&end_user_id)
        .execute(&state.pool)
        .await
        .map_err(AppError::Database)?;

    let revoked_count = result.rows_affected();

    Ok(Json(serde_json::json!({
        "message": "Sessions revoked successfully",
        "revoked_count": revoked_count
    })))
}
