use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore,
    user_passkeys::UserPasskeysStore, users::UserStore, DB,
};
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};

#[derive(Debug, Deserialize)]
pub struct ForgetUserRequest {
    pub current_password: Option<String>,
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ForgetUserResponse {
    pub success: bool,
    pub message: String,
    pub user_id: String,
}

async fn verify_self_delete_authorization(
    state: &AppState,
    user: &crate::entities::users::Model,
    req: &ForgetUserRequest,
) -> Result<()> {
    if let Some(code) = req
        .mfa_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if crate::handlers::user::verify_mfa_code(&state.db, &user.id, code).await? {
            return Ok(());
        }
    }

    if let Some(password) = req
        .current_password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        let password_hash = user.password_hash.as_ref().ok_or_else(|| {
            AppError::BadRequest(
                "Password verification is not available for this account. Verify with MFA instead."
                    .to_string(),
            )
        })?;

        let password_hash_clone = password_hash.clone();
        let password_input = password.to_string();
        let _permit = crate::services::concurrency::ARGON2_SEMAPHORE
            .acquire()
            .await
            .map_err(|_| {
                AppError::InternalServerError("Password verification unavailable".to_string())
            })?;

        let is_valid = tokio::task::spawn_blocking(move || {
            let parsed_hash = match PasswordHash::new(&password_hash_clone) {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::error!("Corrupted password hash in database: {}", e);
                    return false;
                }
            };

            Argon2::default()
                .verify_password(password_input.as_bytes(), &parsed_hash)
                .is_ok()
        })
        .await
        .map_err(|e| {
            AppError::InternalServerError(format!("Password verification failed: {}", e))
        })?;

        if is_valid {
            return Ok(());
        }
    }

    Err(AppError::Forbidden(
        "Confirm account deletion with your current password or MFA code".to_string(),
    ))
}

#[derive(Debug, Serialize)]
pub struct ExportUserDataResponse {
    pub user_id: String,
    pub email: String,
    pub created_at: String,
    pub memberships: Vec<MembershipExport>,
    pub login_events_count: i64,
    pub login_events: Vec<LoginEventExport>,
    pub oauth_identities: Vec<OAuthIdentityExport>,
    pub mfa_events: Vec<MfaEventExport>,
    pub passkeys: Vec<PasskeyExport>,
}

#[derive(Debug, Serialize)]
pub struct MembershipExport {
    pub organization_id: String,
    pub organization_slug: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Serialize)]
pub struct LoginEventExport {
    pub id: String,
    pub timestamp: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub provider: Option<String>,
    pub success: bool,
    pub risk_score: Option<i32>,
    pub risk_factors: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthIdentityExport {
    pub provider: String,
    pub provider_user_id: String,
    pub linked_at: String,
}

#[derive(Debug, Serialize)]
pub struct MfaEventExport {
    pub event_type: String,
    pub timestamp: String,
    pub success: bool,
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyExport {
    pub id: String,
    pub name: Option<String>,
    pub aaguid: Option<String>,
    pub backup_eligible: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// GDPR Right to be Forgotten - Anonymize user data
/// DELETE /api/privacy/forget/{user_id}
/// Requires: Organization owner permission for all organizations the user is a member of
pub async fn forget_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(user_id): Path<String>,
    payload: Option<Json<ForgetUserRequest>>,
) -> Result<Json<ForgetUserResponse>> {
    let requesting_user = &auth_user.user;

    // Find the target user
    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Prevent platform owners from being anonymized
    if target_user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owners cannot be anonymized".to_string(),
        ));
    }

    if requesting_user.id == user_id {
        let req = payload.map(|Json(req)| req).ok_or_else(|| {
            AppError::BadRequest(
                "Confirm account deletion with your current password or MFA code".to_string(),
            )
        })?;

        verify_self_delete_authorization(&state, &target_user, &req).await?;

        let memberships = MembershipStore::list_by_user(DB::Conn(&state.db), &user_id).await?;

        UserStore::anonymize(DB::Conn(&state.db), &user_id).await?;

        use crate::services::audit_builder::OrgAuditBuilder;
        for membership in memberships {
            let event = OrgAuditBuilder::new(
                &membership.org_id,
                Some(&requesting_user.id),
                "user.anonymized",
            )
            .target("user", &user_id)
            .success(true)
            .details_json(Some(serde_json::json!({
                "reason": "Self-service GDPR Right to be Forgotten"
            })))
            .build();
            state.audit_actor.log_org(event).await;
        }

        tracing::warn!(
            actor_id = %requesting_user.id,
            target_user_id = %user_id,
            "User anonymized their own account for GDPR compliance"
        );

        return Ok(Json(ForgetUserResponse {
            success: true,
            message:
                "Your account data has been anonymized. PII has been removed while preserving audit logs."
                    .to_string(),
            user_id,
        }));
    }

    // Get all organizations the target user is a member of
    let memberships = MembershipStore::list_by_user(DB::Conn(&state.db), &user_id).await?;

    // Check if requesting user has owner permission in ALL organizations
    // where the target user is a member
    for membership in &memberships {
        // Check if requesting user is owner of this organization
        let requesting_membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&state.db),
            &membership.org_id,
            &requesting_user.id,
        )
        .await?;

        match requesting_membership {
            Some(req_membership) if req_membership.role == "owner" => {
                // Requesting user is owner - allowed
            }
            _ => {
                // Requesting user is not owner or not a member
                // Check if they're platform owner
                if !requesting_user.is_platform_owner {
                    let org =
                        OrganizationStore::find_by_id(DB::Conn(&state.db), &membership.org_id)
                            .await?
                            .ok_or_else(|| {
                                AppError::NotFound("Organization not found".to_string())
                            })?;

                    return Err(AppError::Forbidden(format!(
                        "You must be an owner of organization '{}' to anonymize this user",
                        org.slug
                    )));
                }
            }
        }
    }

    // Anonymize the user (includes transaction)
    UserStore::anonymize(DB::Conn(&state.db), &user_id).await?;

    // Non-blocking audit via actor for all organizations
    use crate::services::audit_builder::OrgAuditBuilder;
    for membership in memberships {
        let event = OrgAuditBuilder::new(
            &membership.org_id,
            Some(&requesting_user.id),
            "user.anonymized",
        )
        .target("user", &user_id)
        .success(true)
        .details_json(Some(
            serde_json::json!({"reason": "GDPR Right to be Forgotten"}),
        ))
        .build();
        state.audit_actor.log_org(event).await;
    }

    tracing::warn!(
        actor_id = %requesting_user.id,
        target_user_id = %user_id,
        "User anonymized for GDPR compliance"
    );

    Ok(Json(ForgetUserResponse {
        success: true,
        message: "User data has been anonymized. PII has been removed while preserving audit logs."
            .to_string(),
        user_id,
    }))
}

/// GDPR Right to Access - Export user data
/// GET /api/privacy/export/{user_id}
/// Requires: User must be requesting their own data OR be an org owner
pub async fn export_user_data(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<ExportUserDataResponse>> {
    let requesting_user = &auth_user.user;

    // Users can export their own data
    // Or platform owners can export any user's data
    // Or org owners can export their members' data
    let can_export = if requesting_user.id == user_id {
        true
    } else if requesting_user.is_platform_owner {
        true
    } else {
        // Check if requesting user is owner in any org where target user is a member
        let target_memberships =
            MembershipStore::list_by_user(DB::Conn(&state.db), &user_id).await?;

        let mut is_owner_anywhere = false;
        for membership in &target_memberships {
            if let Some(req_membership) = MembershipStore::find_by_org_and_user(
                DB::Conn(&state.db),
                &membership.org_id,
                &requesting_user.id,
            )
            .await?
            {
                if req_membership.role == "owner" {
                    is_owner_anywhere = true;
                    break;
                }
            }
        }

        is_owner_anywhere
    };

    if !can_export {
        return Err(AppError::Forbidden(
            "You do not have permission to export this user's data".to_string(),
        ));
    }

    // Find the target user
    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Get memberships with organization details
    let memberships = MembershipStore::list_by_user(DB::Conn(&state.db), &user_id).await?;

    let mut membership_exports = Vec::new();
    for membership in memberships {
        if let Some(org) =
            OrganizationStore::find_by_id(DB::Conn(&state.db), &membership.org_id).await?
        {
            membership_exports.push(MembershipExport {
                organization_id: membership.org_id,
                organization_slug: org.slug,
                role: membership.role,
                joined_at: DateTime::<Utc>::from_naive_utc_and_offset(membership.created_at, Utc)
                    .to_rfc3339(),
            });
        }
    }

    // Get login events with details
    use crate::entities::prelude::{LoginEvents, MfaAuditLog};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
    let login_events = LoginEvents::find()
        .filter(crate::entities::login_events::Column::UserId.eq(&user_id))
        .order_by_desc(crate::entities::login_events::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let login_count = login_events.len() as i64;
    let mut login_event_exports = Vec::new();
    for event in login_events {
        login_event_exports.push(LoginEventExport {
            id: event.id,
            timestamp: DateTime::<Utc>::from_naive_utc_and_offset(event.created_at, Utc)
                .to_rfc3339(),
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            provider: Some(event.provider),
            success: true, // login_events table only stores successful logins
            risk_score: event.risk_score,
            risk_factors: event.risk_factors,
            geo_country: event.geo_country,
            geo_city: event.geo_city,
        });
    }

    // Get OAuth identities
    use crate::entities::prelude::Identities;
    let identities = Identities::find()
        .filter(crate::entities::identities::Column::UserId.eq(&user_id))
        .all(&state.db)
        .await?;
    let mut identity_exports = Vec::new();
    for identity in identities {
        identity_exports.push(OAuthIdentityExport {
            provider: identity.provider,
            provider_user_id: identity.provider_user_id,
            linked_at: DateTime::<Utc>::from_naive_utc_and_offset(identity.created_at, Utc)
                .to_rfc3339(),
        });
    }

    // Get MFA audit log
    let mfa_events = MfaAuditLog::find()
        .filter(crate::entities::mfa_audit_log::Column::UserId.eq(&user_id))
        .order_by_desc(crate::entities::mfa_audit_log::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let mut mfa_event_exports = Vec::new();
    for event in mfa_events {
        mfa_event_exports.push(MfaEventExport {
            event_type: event.event_type,
            timestamp: DateTime::<Utc>::from_naive_utc_and_offset(event.created_at, Utc)
                .to_rfc3339(),
            success: event.success,
            details: event.details,
        });
    }

    // Get passkeys
    let passkeys = UserPasskeysStore::list_by_user(DB::Conn(&state.db), &user_id).await?;
    let mut passkey_exports = Vec::new();
    for passkey in passkeys {
        passkey_exports.push(PasskeyExport {
            id: passkey.id,
            name: Some(passkey.name),
            aaguid: passkey.aaguid,
            backup_eligible: passkey.backup_eligible,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(passkey.created_at, Utc)
                .to_rfc3339(),
            last_used_at: passkey
                .last_used_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        });
    }

    tracing::info!(
        actor_id = %requesting_user.id,
        target_user_id = %user_id,
        login_events = login_count,
        identities = identity_exports.len(),
        mfa_events = mfa_event_exports.len(),
        passkeys = passkey_exports.len(),
        "User data exported for GDPR compliance"
    );

    Ok(Json(ExportUserDataResponse {
        user_id: target_user.id,
        email: target_user.email,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(target_user.created_at, Utc)
            .to_rfc3339(),
        memberships: membership_exports,
        login_events_count: login_count,
        login_events: login_event_exports,
        oauth_identities: identity_exports,
        mfa_events: mfa_event_exports,
        passkeys: passkey_exports,
    }))
}
