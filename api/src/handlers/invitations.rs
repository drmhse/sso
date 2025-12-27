use crate::constants::{DEFAULT_MAX_USERS, INVITATION_EXPIRY_DAYS, VALID_INVITATION_ROLES};
use crate::entities::{organization_invitations, organizations, users};
use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    invitations::InvitationStore, memberships::MembershipStore,
    organization_tiers::OrganizationTierStore, organizations::OrganizationStore, users::UserStore,
    DB,
};
use axum::{
    extract::{Path, Query, State},
    response::Redirect,
    Json,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Hash an invitation token using SHA256
fn hash_invitation_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

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
    pub invitation: organization_invitations::Model,
    pub inviter: users::Model,
    pub token: String, // Plaintext token for email links (only returned once)
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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin
    let _membership =
        crate::middleware::check_org_admin(&state.db, &user.id, &organization.id).await?;

    // Validate role
    if !VALID_INVITATION_ROLES.contains(&req.role.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid role. Must be one of: {}",
            VALID_INVITATION_ROLES.join(", ")
        )));
    }

    // Check if email is already a member
    let is_member =
        MembershipStore::is_email_member(DB::Conn(&state.db), &organization.id, &req.email).await?;

    if is_member {
        return Err(AppError::BadRequest(
            "User is already a member of this organization".to_string(),
        ));
    }

    // Check for existing pending invitation
    let pending_count = InvitationStore::count_pending_by_org_and_email(
        DB::Conn(&state.db),
        &organization.id,
        &req.email,
    )
    .await?;

    if pending_count > 0 {
        return Err(AppError::BadRequest("Invitation already sent".to_string()));
    }

    // Create invitation
    let invitation_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string(); // Generate plaintext token
    let token_hash = hash_invitation_token(&token); // Hash for storage
    let expires_at = Utc::now() + ChronoDuration::days(INVITATION_EXPIRY_DAYS);

    // Log invitation creation
    tracing::info!(
        org_slug = %org_slug,
        invited_email = %req.email,
        role = %req.role,
        inviter_id = %user.id,
        "Creating organization invitation"
    );

    let new_invitation = organization_invitations::ActiveModel {
        id: Set(invitation_id),
        org_id: Set(organization.id.clone()),
        email: Set(req.email.clone()),
        role: Set(req.role.clone()),
        invited_by: Set(user.id.clone()),
        status: Set("pending".to_string()),
        token: Set(token_hash),
        expires_at: Set(expires_at.naive_utc()),
        created_at: Set(Utc::now().naive_utc()),
        ..Default::default()
    };

    let invitation = new_invitation.insert(&state.db).await?;

    // Get inviter details
    let inviter = UserStore::find_by_id(DB::Conn(&state.db), &user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Enqueue invitation email to job queue (non-blocking)
    let invitation_url = format!("{}/invitations/accept/{}", state.base_url, token);
    let email_subject = format!("You've been invited to join {}", organization.name);
    let email_body = format!(
        "{} ({}) has invited you to join {} as a {}.\n\n\
        Click the link below to accept or decline this invitation:\n\n\
        {}\n\n\
        This invitation will expire in 7 days.\n\n\
        If you don't recognize this invitation, you can safely ignore this email.",
        inviter.email, inviter.email, organization.name, req.role, invitation_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &req.email,
        &email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::warn!(
            org_slug = %org_slug,
            invited_email = %req.email,
            error = %e,
            "Failed to enqueue invitation email, but invitation was created"
        );
    } else {
        tracing::info!(
            org_slug = %org_slug,
            invited_email = %req.email,
            "Invitation email enqueued successfully"
        );
    }

    Ok(Json(InvitationResponse {
        invitation,
        inviter,
        token, // Return plaintext token for email links
    }))
}

/// List user's pending invitations
pub async fn list_user_invitations(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>> {
    let user = &auth_user.user;

    let invitations =
        InvitationStore::list_user_pending_invitations(DB::Conn(&state.db), &user.email).await?;

    let responses: Vec<serde_json::Value> = invitations
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "email": row.email,
                "role": row.role,
                "token": row.token,
                "expires_at": DateTime::<Utc>::from_naive_utc_and_offset(row.expires_at, Utc).to_rfc3339(),
                "created_at": DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc).to_rfc3339(),
                "organization_slug": row.org_slug,
                "organization_name": row.org_name
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
    // Hash the token to look it up
    let token_hash = hash_invitation_token(&token);
    let new_status = new_status.to_string();

    // Execute transaction with retry on database contention
    let affected_user_id = with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "accept_invitation", |db| {
        let token_hash = token_hash.clone();
        let new_status = new_status.clone();
        Box::pin(async move {
            // Find invitation
            use crate::entities::prelude::OrganizationInvitations;
            let invitation = OrganizationInvitations::find()
                .filter(organization_invitations::Column::Token.eq(&token_hash))
                .filter(organization_invitations::Column::Status.eq("pending"))
                .one(&db)
                .await?
                .ok_or_else(|| {
                    AppError::NotFound("Invitation not found or already processed".to_string())
                })?;

            // Check if expired
            let expires_at = DateTime::<Utc>::from_naive_utc_and_offset(invitation.expires_at, Utc);

            if expires_at < Utc::now() {
                return Err(AppError::BadRequest("Invitation has expired".to_string()));
            }

            // Track user_id for cache invalidation
            let mut affected_user_id: Option<String> = None;

            if new_status == "accepted" {
                // Find or create user
                let user = find_or_create_user_internal(db.clone(), &invitation.email).await?;
                affected_user_id = Some(user.id.clone());

                // Check team limits
                let member_count =
                    MembershipStore::count_by_org(db.clone(), &invitation.org_id, None).await?;

                // Get organization limits
                use crate::entities::prelude::Organizations;
                let org = Organizations::find()
                    .filter(organizations::Column::Id.eq(&invitation.org_id))
                    .one(&db)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let tier_limit = if let (Some(max_users), Some(_tier_id)) =
                    (org.max_users, org.tier_id.as_ref())
                {
                    // Use org-specific limit if set
                    max_users as i64
                } else if let Some(tier_id) = org.tier_id.as_ref() {
                    // Use tier default
                    let tier = OrganizationTierStore::find_by_id(db.clone(), tier_id)
                        .await?
                        .ok_or_else(|| AppError::NotFound("Tier not found".to_string()))?;

                    tier.default_max_users as i64
                } else {
                    DEFAULT_MAX_USERS // Free tier default
                };

                if member_count >= tier_limit as u64 {
                    return Err(AppError::BadRequest("Team limit reached".to_string()));
                }

                // Create membership
                use crate::entities::memberships;
                let new_membership = memberships::ActiveModel {
                    id: Set(Uuid::new_v4().to_string()),
                    org_id: Set(invitation.org_id.clone()),
                    user_id: Set(user.id.clone()),
                    role: Set(invitation.role.clone()),
                    created_at: Set(Utc::now().naive_utc()),
                    ..Default::default()
                };
                new_membership.insert(&db).await?;

                // Grant organization permission for the new member
                use crate::entities::permissions::RelationTuple;
                use crate::store::permissions::PermissionsStore;
                PermissionsStore::grant(
                    db.clone(),
                    RelationTuple::user(
                        "organization".to_string(),
                        invitation.org_id.clone(),
                        invitation.role.clone(),
                        user.id.clone(),
                    ),
                )
                .await?;
            }

            // Update invitation status
            let mut invitation_active: organization_invitations::ActiveModel = invitation.into();
            invitation_active.status = Set(new_status);
            invitation_active.update(&db).await?;

            Ok(affected_user_id)
        })
    })
    .await?;

    // CRITICAL: Invalidate permission cache after accepting invitation
    if let Some(user_id) = affected_user_id {
        state.permission_cache.invalidate(&user_id).await;
    }

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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin
    let _membership =
        crate::middleware::check_org_admin(&state.db, &user.id, &organization.id).await?;

    // Cancel invitation - find it first, then update
    use crate::entities::prelude::OrganizationInvitations;
    let invitation = OrganizationInvitations::find()
        .filter(organization_invitations::Column::Id.eq(&invitation_id))
        .filter(organization_invitations::Column::OrgId.eq(&organization.id))
        .filter(organization_invitations::Column::Status.eq("pending"))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("Invitation not found or already processed".to_string())
        })?;

    let mut invitation_active: organization_invitations::ActiveModel = invitation.into();
    invitation_active.status = Set("cancelled".to_string());
    invitation_active.update(&state.db).await?;

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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner or admin
    let _membership =
        crate::middleware::check_org_admin(&state.db, &user.id, &organization.id).await?;

    // Extract pagination parameters with defaults
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Get invitations for this organization with pagination
    let invitations = InvitationStore::list_org_invitations_with_inviter(
        DB::Conn(&state.db),
        &organization.id,
        limit,
        offset,
    )
    .await?;

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
                    "expires_at": DateTime::<Utc>::from_naive_utc_and_offset(row.expires_at, Utc).to_rfc3339(),
                    "created_at": DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc).to_rfc3339()
                },
                "inviter": {
                    "id": row.inviter_id,
                    "email": row.inviter_email,
                    "created_at": DateTime::<Utc>::from_naive_utc_and_offset(row.inviter_created_at, Utc).to_rfc3339()
                }
            })
        })
        .collect();

    Ok(Json(responses))
}

/// Helper function to find or create a user within a transaction (for invitation acceptance)
async fn find_or_create_user_internal(
    db: DB<'_>,
    email: &str,
) -> Result<users::Model> {
    // Check if user exists
    use crate::entities::prelude::Users;
    if let Some(user) = Users::find()
        .filter(users::Column::Email.eq(email))
        .one(&db)
        .await?
    {
        return Ok(user);
    }

    // Create new user
    let new_user = users::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        email: Set(email.to_string()),
        created_at: Set(Utc::now().naive_utc()),
        ..Default::default()
    };

    let user = new_user.insert(&db).await?;
    Ok(user)
}
