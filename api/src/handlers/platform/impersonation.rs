//! Impersonation Handlers
//!
//! Implements platform impersonation functionality following RFC 8693 (Token Exchange)
//! Allows platform owners and organization admins to impersonate users for support purposes.

use crate::entities::{platform_audit_log, users as users_entity};
use crate::error::AppError;
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{memberships::MembershipStore, organizations::OrganizationStore, DB};
use axum::{
    extract::{Extension, Json, State},
    response::Json as AxumJson,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// Request to impersonate a user
#[derive(Debug, Deserialize)]
pub struct ImpersonateRequest {
    /// User ID to impersonate
    pub user_id: String,
    /// Reason for impersonation (required for audit trail)
    pub reason: String,
}

/// Response containing impersonation token
#[derive(Debug, Serialize)]
pub struct ImpersonateResponse {
    /// JWT token for impersonated session
    pub token: String,
    /// Information about the impersonated user
    pub target_user: UserInfo,
    /// Information about the admin performing impersonation
    pub actor_user: UserInfo,
}

/// Basic user information
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

/// Impersonate a user
///
/// This endpoint allows platform owners to impersonate any user, and organization admins
/// to impersonate users within their organization. All impersonation actions are logged
/// to the audit trail with high severity.
///
/// # Security Considerations
/// - Tokens have very short TTL (15 minutes)
/// - All actions during impersonation are logged with actor context
/// - Impersonation is tracked in audit logs with HIGH severity
/// - Supports both platform owner and org admin impersonation
pub async fn impersonate_user(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(request): Json<ImpersonateRequest>,
) -> crate::error::Result<AxumJson<ImpersonateResponse>> {
    let db = &state.db;

    // Validate the target user exists and get their details
    let target_user = users_entity::Entity::find_by_id(request.user_id.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::NotFound("Target user not found".to_string()))?;

    // Check authorization based on platform owner status or org admin status
    let can_impersonate = if auth_user.user.is_platform_owner {
        // Platform owners can impersonate any user
        true
    } else {
        // Check if target user is in the same organization and auth user is an org admin
        let target_memberships =
            MembershipStore::list_by_user(DB::Conn(db), &target_user.id).await?;

        let mut is_admin_of_target = false;

        for membership in target_memberships {
            if let Some(caller_membership) = MembershipStore::find_by_org_and_user(
                DB::Conn(db),
                &membership.org_id,
                &auth_user.user.id,
            )
            .await?
            {
                if caller_membership.role == "owner" || caller_membership.role == "admin" {
                    is_admin_of_target = true;
                    break;
                }
            }
        }

        is_admin_of_target
    };

    if !can_impersonate {
        return Err(AppError::Forbidden(
            "You don't have permission to impersonate this user".to_string(),
        ));
    }

    // Get target user's organization and permission context
    let target_memberships = MembershipStore::list_by_user(DB::Conn(db), &target_user.id).await?;

    let (org_slug, service_slug) = if let Some(first_membership) = target_memberships.first() {
        // Get org slug from first membership
        let org = OrganizationStore::find_by_id(DB::Conn(db), &first_membership.org_id).await?;

        if let Some(org) = org {
            // For now, we use the first organization context
            // In a production system, impersonation request should specify which org context
            (Some(org.slug), None::<String>)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Create impersonation token with actual context
    let jwt_service = &state.jwt_service;
    let impersonation_token = jwt_service.create_impersonation_token(
        &target_user.id,
        &target_user.email,
        &auth_user.user.id,
        &auth_user.user.email,
        Some(&request.reason),
        org_slug.as_deref(),     // Actual org context
        service_slug.as_deref(), // Service context (if available)
        target_user.is_platform_owner,
    )?;

    // Create HIGH SEVERITY audit log entry
    let metadata = json!({
        "target_user_email": target_user.email,
        "reason": request.reason,
        "actor_email": auth_user.user.email,
        "severity": "HIGH"
    });

    let audit_log = platform_audit_log::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        platform_owner_id: Set(auth_user.user.id.clone()),
        action: Set("user.impersonate".to_string()),
        target_type: Set("user".to_string()),
        target_id: Set(target_user.id.clone()),
        metadata: Set(Some(metadata.to_string())),
        created_at: Set(Utc::now().naive_utc()),
    };

    audit_log.insert(db).await?;

    tracing::warn!(
        admin_user_id = %auth_user.user.id,
        admin_user_email = %auth_user.user.email,
        target_user_id = %target_user.id,
        target_user_email = %target_user.email,
        reason = %request.reason,
        "User impersonation initiated"
    );

    // Prepare response data with org context
    let (target_org_id, target_org_name) =
        if let Some(first_membership) = target_memberships.first() {
            if let Ok(Some(org)) =
                OrganizationStore::find_by_id(DB::Conn(db), &first_membership.org_id).await
            {
                (Some(org.id), Some(org.name))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

    let target_user_info = UserInfo {
        id: target_user.id.clone(),
        email: target_user.email.clone(),
        is_platform_owner: target_user.is_platform_owner,
        org_id: target_org_id,
        org_name: target_org_name,
    };

    let actor_user_info = UserInfo {
        id: auth_user.user.id.clone(),
        email: auth_user.user.email.clone(),
        is_platform_owner: auth_user.user.is_platform_owner,
        org_id: None, // Actor context not needed in response
        org_name: None,
    };

    Ok(AxumJson(ImpersonateResponse {
        token: impersonation_token,
        target_user: target_user_info,
        actor_user: actor_user_info,
    }))
}
