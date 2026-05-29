use crate::constants::{DEFAULT_MAX_USERS, DEFAULT_TIER_NAME, VALID_ORG_ROLES};
use crate::entities::{memberships, users};
use crate::error::{AppError, Result, with_retrying_transaction};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{
    CAP_ORG_MEMBERS_MANAGE, CAP_ORG_ROLES_MANAGE, PermissionService,
};
use crate::state::AppState;
use crate::store::{
    DB, memberships::MembershipStore, organization_roles::OrganizationRoleStore,
    organization_tiers::OrganizationTierStore, organizations::OrganizationStore,
    permissions::PermissionsStore, services::ServiceStore, users::UserStore,
};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct OrganizationMember {
    pub user: users::Model,
    pub membership: memberships::Model,
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
pub struct TransferOwnershipRequest {
    pub new_owner_email: String,
}

#[derive(Debug, Serialize)]
pub struct MemberServiceAccess {
    pub service_id: String,
    pub service_slug: String,
    pub service_name: String,
    pub access: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberServiceAccessRequest {
    pub grants: Vec<MemberServiceAccessGrant>,
}

#[derive(Debug, Deserialize)]
pub struct MemberServiceAccessGrant {
    pub service_slug: String,
    pub access: Option<String>,
}

async fn validate_org_role(db: DB<'_>, org_id: &str, role: &str) -> Result<()> {
    if role == "owner" || VALID_ORG_ROLES.contains(&role) {
        return Ok(());
    }

    if OrganizationRoleStore::find_by_org_and_slug(db, org_id, role)
        .await?
        .is_some()
    {
        return Ok(());
    }

    Err(AppError::BadRequest(
        "Invalid role. Choose a system role or custom organization role.".to_string(),
    ))
}

async fn can_manage_members(state: &AppState, org_id: &str, user_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_ORG_MEMBERS_MANAGE).await
}

async fn can_manage_roles(state: &AppState, org_id: &str, user_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_ORG_ROLES_MANAGE).await
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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    crate::middleware::check_org_membership(&state.db, &user.id, &organization.id, &[]).await?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Get members with user details using store layer
    let members = MembershipStore::list_with_users(
        DB::Conn(&state.db),
        &organization.id,
        query.role.as_deref(),
        limit,
        offset,
    )
    .await?;

    let member_responses: Vec<OrganizationMember> = members
        .into_iter()
        .map(|row| {
            let user = users::Model {
                id: row.user_id.clone(),
                email: row.user_email,
                org_id: None,
                is_platform_owner: row.user_is_platform_owner,
                password_hash: None,
                email_verified_at: None,
                created_at: row.user_created_at,
                updated_at: None,
                deleted_at: None,
            };
            let membership = memberships::Model {
                id: row.membership_id,
                org_id: organization.id.clone(),
                user_id: row.user_id,
                role: row.membership_role,
                created_at: row.membership_created_at,
            };
            OrganizationMember { user, membership }
        })
        .collect();

    // Get total member count
    let total_members =
        MembershipStore::count_by_org(DB::Conn(&state.db), &organization.id, None).await? as i64;

    // Get organization limits
    let (max_users, limit_source) = if let Some(custom_limit) = organization.max_users {
        (custom_limit as i64, "custom".to_string())
    } else {
        // Get tier default
        let tier =
            OrganizationTierStore::find_by_org_id(DB::Conn(&state.db), &organization.id).await?;

        if let Some(tier) = tier {
            (tier.default_max_users as i64, tier.name)
        } else {
            (DEFAULT_MAX_USERS, DEFAULT_TIER_NAME.to_string())
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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_roles(&state, &organization.id, &user.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to change member roles".to_string(),
        ));
    }

    validate_org_role(DB::Conn(&state.db), &organization.id, &req.role).await?;

    // Cannot change own role (prevent self-demotion from owner)
    if user_id == user.id {
        return Err(AppError::BadRequest(
            "Cannot change your own role".to_string(),
        ));
    }

    // Get target membership
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("User is not a member of this organization".to_string())
            })?;

    if matches!(membership.role.as_str(), "owner" | "admin") || req.role == "owner" {
        crate::middleware::check_org_owner(&state.db, &user.id, &organization.id).await?;
    }

    // Update role
    MembershipStore::update_role(DB::Conn(&state.db), &membership.id, &req.role).await?;

    // Sync permissions: revoke old role permission and grant new role permission
    use crate::entities::permissions::SUBJECT_TYPE_USER;
    use crate::store::permissions::PermissionsStore;

    // Revoke old role permission
    PermissionsStore::revoke(
        DB::Conn(&state.db),
        "organization",
        &organization.id,
        &membership.role,
        SUBJECT_TYPE_USER,
        &user_id,
        None,
    )
    .await?;

    let services = ServiceStore::list_by_org(DB::Conn(&state.db), &organization.id).await?;
    for service in services {
        for relation in ["viewer", "manager"] {
            PermissionsStore::revoke(
                DB::Conn(&state.db),
                "service",
                &service.id,
                relation,
                SUBJECT_TYPE_USER,
                &user_id,
                None,
            )
            .await?;
        }
    }

    // Grant new role permission
    use crate::entities::permissions::RelationTuple;
    PermissionsStore::grant(
        DB::Conn(&state.db),
        RelationTuple::user(
            "organization".to_string(),
            organization.id.clone(),
            req.role.clone(),
            user_id.clone(),
        ),
    )
    .await?;

    // CRITICAL: Invalidate permission cache after role change
    state.permission_cache.invalidate(&user_id).await;

    // Fetch target user for audit logging
    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Non-blocking audit via actor
    let old_role = &membership.role;
    let event = OrgAuditBuilder::new(&organization.id, Some(&user.id), "member.role_changed")
        .target("user", &user_id)
        .success(true)
        .details_json(Some(json!({
            "old_role": old_role,
            "new_role": req.role,
            "target_user_email": target_user.email
        })))
        .build();
    state.audit_actor.log_org(event).await;

    // If setting new owner, update organization and previous owner
    if req.role == "owner" {
        let current_user_id = user.id.clone();
        let org_id = organization.id.clone();
        let new_owner_id = user_id.clone();

        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "transfer_ownership_via_role_update",
            |db| {
                let org_id = org_id.clone();
                let new_owner_id = new_owner_id.clone();
                let current_user_id = current_user_id.clone();
                Box::pin(async move {
                    // Update organization owner
                    OrganizationStore::transfer_ownership(db.clone(), &org_id, &new_owner_id)
                        .await?;

                    // Demote previous owner to admin
                    let prev_owner_membership = MembershipStore::find_by_org_and_user(
                        db.clone(),
                        &org_id,
                        &current_user_id,
                    )
                    .await?
                    .ok_or_else(|| {
                        AppError::NotFound("Previous owner membership not found".to_string())
                    })?;
                    MembershipStore::update_role(db.clone(), &prev_owner_membership.id, "admin")
                        .await?;

                    Ok(())
                })
            },
        )
        .await?;

        // Invalidate permission cache for previous owner as well
        state.permission_cache.invalidate(&user.id).await;

        let ownership_event = OrgAuditBuilder::new(
            &organization.id,
            Some(&user.id),
            "org.ownership_transferred",
        )
        .target("organization", &organization.id)
        .success(true)
        .details_json(Some(json!({
            "previous_owner_email": user.email,
            "new_owner_email": target_user.email,
            "ownership_transferred": true
        })))
        .build();
        state.audit_actor.log_org(ownership_event).await;
    }

    let updated_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_members(&state, &organization.id, &user.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to remove members".to_string(),
        ));
    }

    let caller_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user.id)
            .await?
            .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    // Cannot remove yourself
    if user_id == user.id {
        return Err(AppError::BadRequest(
            "Cannot remove yourself from the organization".to_string(),
        ));
    }

    // Get target membership
    let target_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("User is not a member of this organization".to_string())
            })?;

    // Get target user for audit logging
    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check permissions: owner can remove anyone, admin can only remove members, not owners/admins
    if caller_membership.role != "owner"
        && (target_membership.role == "owner" || target_membership.role == "admin")
    {
        return Err(AppError::Forbidden(
            "Only owners can remove other owners and admins".to_string(),
        ));
    }

    // Remove membership
    MembershipStore::delete(DB::Conn(&state.db), &target_membership.id).await?;

    // Revoke all organization permissions for the user
    use crate::entities::permissions::SUBJECT_TYPE_USER;
    use crate::store::permissions::PermissionsStore;
    PermissionsStore::revoke(
        DB::Conn(&state.db),
        "organization",
        &organization.id,
        &target_membership.role,
        SUBJECT_TYPE_USER,
        &user_id,
        None,
    )
    .await?;

    // CRITICAL: Invalidate permission cache after removing member
    state.permission_cache.invalidate(&user_id).await;

    // Non-blocking audit via actor
    let event = OrgAuditBuilder::new(&organization.id, Some(&user.id), "member.removed")
        .target("user", &user_id)
        .success(true)
        .details_json(Some(json!({
            "removed_user_email": target_user.email,
            "removed_role": target_membership.role,
            "removed_by_role": caller_membership.role
        })))
        .build();
    state.audit_actor.log_org(event).await;

    Ok(Json(()))
}

/// List a member's direct per-service access grants.
pub async fn list_member_service_access(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
) -> Result<Json<Vec<MemberServiceAccess>>> {
    let actor = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_members(&state, &organization.id, &actor.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view service access".to_string(),
        ));
    }

    MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("User is not a member of this organization".to_string())
        })?;

    let services = ServiceStore::list_by_org(DB::Conn(&state.db), &organization.id).await?;
    let mut response = Vec::with_capacity(services.len());

    for service in services {
        let access = if PermissionsStore::check(
            DB::Conn(&state.db),
            "service",
            &service.id,
            "manager",
            &user_id,
        )
        .await?
        {
            Some("manager".to_string())
        } else if PermissionsStore::check(
            DB::Conn(&state.db),
            "service",
            &service.id,
            "viewer",
            &user_id,
        )
        .await?
        {
            Some("viewer".to_string())
        } else {
            None
        };

        response.push(MemberServiceAccess {
            service_id: service.id,
            service_slug: service.slug,
            service_name: service.name,
            access,
        });
    }

    Ok(Json(response))
}

/// Replace a member's direct per-service access grants.
pub async fn update_member_service_access(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberServiceAccessRequest>,
) -> Result<Json<Vec<MemberServiceAccess>>> {
    let actor = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_members(&state, &organization.id, &actor.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to update service access".to_string(),
        ));
    }

    MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("User is not a member of this organization".to_string())
        })?;

    let mut requested_grants = BTreeMap::new();
    for grant in req.grants {
        if let Some(access) = grant.access.as_deref() {
            if access != "viewer" && access != "manager" {
                return Err(AppError::BadRequest(
                    "Service access must be viewer, manager, or null".to_string(),
                ));
            }
        }

        requested_grants.insert(grant.service_slug, grant.access);
    }

    let mut validated_grants = Vec::with_capacity(requested_grants.len());
    for (service_slug, access) in requested_grants {
        let service = ServiceStore::find_by_org_and_slug(
            DB::Conn(&state.db),
            &organization.id,
            &service_slug,
        )
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Service '{}' not found", service_slug)))?;

        validated_grants.push((service.id, access));
    }

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_member_service_access",
        |db| {
            let grants = validated_grants.clone();
            let user_id = user_id.clone();
            Box::pin(async move {
                for (service_id, access) in grants {
                    for relation in ["viewer", "manager"] {
                        PermissionsStore::revoke(
                            db.clone(),
                            "service",
                            &service_id,
                            relation,
                            crate::entities::permissions::SUBJECT_TYPE_USER,
                            &user_id,
                            None,
                        )
                        .await?;
                    }

                    if let Some(access) = access {
                        PermissionsStore::grant(
                            db.clone(),
                            crate::entities::permissions::RelationTuple::user(
                                "service",
                                service_id,
                                access,
                                user_id.clone(),
                            ),
                        )
                        .await?;
                    }
                }

                Ok(())
            })
        },
    )
    .await?;

    state.permission_cache.invalidate(&user_id).await;

    let event = OrgAuditBuilder::new(
        &organization.id,
        Some(&actor.id),
        "member.service_access_updated",
    )
    .target("user", &user_id)
    .success(true)
    .details_json(Some(json!({ "target_user_id": user_id.clone() })))
    .build();
    state.audit_actor.log_org(event).await;

    list_member_service_access(State(state), auth_user, Path((org_slug, user_id))).await
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
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner
    crate::middleware::check_org_owner(&state.db, &user.id, &organization.id).await?;

    // Find new owner by email
    let new_owner = UserStore::find_by_email(DB::Conn(&state.db), &req.new_owner_email)
        .await?
        .ok_or_else(|| AppError::NotFound("User with that email not found".to_string()))?;

    // Check if new owner is a member
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &new_owner.id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("User is not a member of this organization".to_string())
            })?;

    let org_id = organization.id.clone();
    let new_owner_id = new_owner.id.clone();
    let membership_id = membership.id.clone();
    let prev_owner_id = user.id.clone();

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "transfer_ownership",
        |db| {
            let org_id = org_id.clone();
            let new_owner_id = new_owner_id.clone();
            let membership_id = membership_id.clone();
            let prev_owner_id = prev_owner_id.clone();
            Box::pin(async move {
                // Update organization owner
                OrganizationStore::transfer_ownership(db.clone(), &org_id, &new_owner_id).await?;

                // Update membership roles
                MembershipStore::update_role(db.clone(), &membership_id, "owner").await?;

                // Demote previous owner to admin
                let prev_owner_membership =
                    MembershipStore::find_by_org_and_user(db.clone(), &org_id, &prev_owner_id)
                        .await?
                        .ok_or_else(|| {
                            AppError::NotFound("Previous owner membership not found".to_string())
                        })?;
                MembershipStore::update_role(db.clone(), &prev_owner_membership.id, "admin")
                    .await?;

                Ok(())
            })
        },
    )
    .await?;

    // CRITICAL: Invalidate permission cache for both users (new owner and old owner)
    state.permission_cache.invalidate(&new_owner.id).await;
    state.permission_cache.invalidate(&user.id).await;

    // Fetch updated membership
    let updated_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &new_owner.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

    Ok(Json(OrganizationMember {
        user: new_owner,
        membership: updated_membership,
    }))
}
