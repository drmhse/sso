use crate::constants::{DEFAULT_MAX_USERS, INVITATION_EXPIRY_DAYS, VALID_INVITATION_ROLES};
use crate::db::models::{Organization, OrganizationInvitation, User};
use crate::error::{AppError, Result};
use crate::handlers::auth::AppState;
use crate::middleware::AuthUser;
use axum::{
    extract::{Path, Query, State},
    response::Redirect,
    Json,
};
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInvitationRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub invitation: OrganizationInvitation,
    pub inviter: User,
}

#[derive(Debug, Deserialize)]
pub struct ListInvitationsQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    #[allow(dead_code)]
    pub status: Option<String>,
}

/// Create invitation (owner/admin only)
pub async fn create_invitation(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<InvitationResponse>> {
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

    // Validate role
    if !VALID_INVITATION_ROLES.contains(&req.role.as_str()) {
        return Err(AppError::BadRequest(
            format!("Invalid role. Must be one of: {}", VALID_INVITATION_ROLES.join(", ")),
        ));
    }

    // Check if email is already a member
    let existing_member = sqlx::query!(
        "SELECT COUNT(*) as count FROM memberships m
         JOIN users u ON m.user_id = u.id
         WHERE m.org_id = ? AND u.email = ?",
        organization.id,
        req.email
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    if existing_member.count > 0 {
        return Err(AppError::BadRequest(
            "User is already a member of this organization".to_string(),
        ));
    }

    // Check for existing pending invitation
    let existing_invitation = sqlx::query!(
        "SELECT COUNT(*) as count FROM organization_invitations
         WHERE org_id = ? AND email = ? AND status = 'pending'",
        organization.id,
        req.email
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    if existing_invitation.count > 0 {
        return Err(AppError::BadRequest("Invitation already sent".to_string()));
    }

    // Create invitation
    let invitation_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + ChronoDuration::days(INVITATION_EXPIRY_DAYS);

    // Log invitation creation
    tracing::info!(
        org_slug = %org_slug,
        invited_email = %req.email,
        role = %req.role,
        inviter_id = %user.id,
        "Creating organization invitation"
    );

    let invitation = sqlx::query_as::<_, OrganizationInvitation>(
        "INSERT INTO organization_invitations (id, org_id, email, role, invited_by, status, token, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
         RETURNING *"
    )
    .bind(&invitation_id)
    .bind(&organization.id)
    .bind(&req.email)
    .bind(&req.role)
    .bind(&user.id)
    .bind(&token)
    .bind(expires_at)
    .bind(Utc::now())
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // Get inviter details
    let inviter = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(InvitationResponse {
        invitation,
        inviter,
    }))
}

/// List user's pending invitations
pub async fn list_user_invitations(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>> {
    let user = &auth_user.user;

    let rows = sqlx::query!(
        r#"
        SELECT
            i.id, i.email, i.role, i.token, i.expires_at, i.created_at,
            o.slug as org_slug, o.name as org_name
        FROM organization_invitations i
        JOIN organizations o ON i.org_id = o.id
        WHERE i.email = ? AND i.status = 'pending'
        ORDER BY i.created_at DESC
        "#,
        user.email
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let invitations: Vec<InvitationBasic> = rows
        .into_iter()
        .map(|row| InvitationBasic {
            id: row.id.unwrap_or_default(),
            email: row.email,
            role: row.role,
            token: row.token,
            expires_at: row.expires_at,
            created_at: row.created_at.unwrap_or_default(),
            org_slug: row.org_slug,
            org_name: row.org_name,
        })
        .collect();

    let responses: Vec<serde_json::Value> = invitations
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "email": row.email,
                "role": row.role,
                "token": row.token,
                "expires_at": row.expires_at,
                "created_at": row.created_at,
                "organization": {
                    "slug": row.org_slug,
                    "name": row.org_name
                }
            })
        })
        .collect();

    Ok(Json(responses))
}

/// Accept invitation (public endpoint)
pub async fn accept_invitation(
    State(state): State<AppState>,
    Json(req): Json<UpdateInvitationRequest>,
) -> Result<Json<()>> {
    accept_invitation_internal(State(state), req.token, "accepted").await
}

/// Decline invitation (public endpoint)
pub async fn decline_invitation(
    State(state): State<AppState>,
    Json(req): Json<UpdateInvitationRequest>,
) -> Result<Json<()>> {
    accept_invitation_internal(State(state), req.token, "rejected").await
}

/// Internal invitation acceptance/rejection logic
async fn accept_invitation_internal(
    state: State<AppState>,
    token: String,
    new_status: &str,
) -> Result<Json<()>> {
    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Find invitation
    let invitation = sqlx::query_as::<_, OrganizationInvitation>(
        "SELECT * FROM organization_invitations WHERE token = ? AND status = 'pending'",
    )
    .bind(&token)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Invitation not found or already processed".to_string()))?;

    // Check if expired
    if invitation.expires_at < Utc::now() {
        return Err(AppError::BadRequest("Invitation has expired".to_string()));
    }

    if new_status == "accepted" {
        // Find or create user
        let user = find_or_create_user_tx(&mut tx, &invitation.email).await?;

        // Check team limits
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM memberships WHERE org_id = ?")
                .bind(&invitation.org_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::Database)?;

        // Get organization limits
        let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
            .bind(&invitation.org_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        let tier_limit =
            if let (Some(max_users), Some(_tier_id)) = (org.max_users, org.tier_id.as_ref()) {
                // Use org-specific limit if set
                max_users
            } else if let Some(tier_id) = org.tier_id.as_ref() {
                // Use tier default
                let tier = sqlx::query!(
                    "SELECT default_max_users FROM organization_tiers WHERE id = ?",
                    tier_id
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                tier.default_max_users
            } else {
                DEFAULT_MAX_USERS // Free tier default
            };

        if member_count >= tier_limit {
            return Err(AppError::BadRequest("Team limit reached".to_string()));
        }

        // Create membership
        let membership_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        sqlx::query!(
            "INSERT INTO memberships (id, org_id, user_id, role, created_at)
             VALUES (?, ?, ?, ?, ?)",
            membership_id,
            invitation.org_id,
            user.id,
            invitation.role,
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }

    // Update invitation status
    sqlx::query!(
        "UPDATE organization_invitations SET status = ? WHERE id = ?",
        new_status,
        invitation.id
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(()))
}

/// Accept invitation via email link (redirect)
pub async fn accept_invitation_redirect(
    State(_state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Redirect> {
    // For now, redirect to a simple success page
    // In production, this would redirect to your web app
    Ok(Redirect::permanent(&format!(
        "/invitations/accept?token={}",
        token
    )))
}

/// Cancel invitation (owner/admin only)
pub async fn cancel_invitation(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, invitation_id)): Path<(String, String)>,
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

    // Check if user is owner or admin
    let _membership =
        crate::middleware::check_org_admin(&state.pool, &user.id, &organization.id).await?;

    // Cancel invitation
    let result = sqlx::query!(
        "UPDATE organization_invitations SET status = 'cancelled'
         WHERE id = ? AND org_id = ? AND status = 'pending'",
        invitation_id,
        organization.id
    )
    .execute(&state.pool)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Invitation not found or already processed".to_string(),
        ));
    }

    Ok(Json(()))
}

/// List organization invitations (owner/admin only)
pub async fn list_invitations(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    query: Query<ListInvitationsQuery>,
) -> Result<Json<Vec<serde_json::Value>>> {
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

    // Extract pagination parameters with defaults
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Get invitations for this organization with pagination
    let rows = sqlx::query!(
        r#"
        SELECT
            i.id, i.email, i.role, i.status, i.token, i.expires_at, i.created_at,
            u.email as inviter_email, u.id as inviter_id, u.created_at as inviter_created_at
        FROM organization_invitations i
        JOIN users u ON i.invited_by = u.id
        WHERE i.org_id = ?
        ORDER BY i.created_at DESC
        LIMIT ? OFFSET ?
        "#,
        organization.id,
        limit,
        offset
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let invitations: Vec<InvitationWithInviter> = rows
        .into_iter()
        .map(|row| InvitationWithInviter {
            id: row.id.unwrap_or_default(),
            email: row.email,
            role: row.role,
            status: row.status,
            token: row.token,
            expires_at: row.expires_at,
            created_at: row.created_at.unwrap_or_default(),
            inviter_email: row.inviter_email,
            inviter_id: row.inviter_id.unwrap_or_default(),
            inviter_created_at: row.inviter_created_at.unwrap_or_default(),
        })
        .collect();

    let responses: Vec<serde_json::Value> = invitations
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "invitation": {
                    "id": row.id,
                    "email": row.email,
                    "role": row.role,
                    "status": row.status,
                    "token": row.token,
                    "expires_at": row.expires_at,
                    "created_at": row.created_at
                },
                "inviter": {
                    "id": row.inviter_id,
                    "email": row.inviter_email,
                    "created_at": row.inviter_created_at
                }
            })
        })
        .collect();

    Ok(Json(responses))
}

/// Helper function to find or create a user (for invitation acceptance)
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

// Simplified structs for query results
#[derive(Debug)]
struct InvitationBasic {
    id: String,
    email: String,
    role: String,
    token: String,
    expires_at: chrono::NaiveDateTime,
    created_at: chrono::NaiveDateTime,
    org_slug: String,
    org_name: String,
}

#[derive(Debug)]
struct InvitationWithInviter {
    id: String,
    email: String,
    role: String,
    status: String,
    token: String,
    expires_at: chrono::NaiveDateTime,
    created_at: chrono::NaiveDateTime,
    inviter_email: String,
    inviter_id: String,
    inviter_created_at: chrono::NaiveDateTime,
}
