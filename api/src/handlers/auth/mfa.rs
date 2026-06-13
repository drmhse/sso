use crate::auth::jwt::Claims;
use crate::db::models::User;
use crate::entities::users;
use crate::error::{with_deadlock_retry, with_retrying_transaction, AppError, Result};
use crate::middleware::RequestInfo;
use crate::services::audit_builder::MfaAuditBuilder;
use crate::state::AppState;
use crate::store::{
    device_codes::DeviceCodeStore, distributed_locks::DistributedLockStore, services::ServiceStore,
    sessions::SessionStore, DB,
};
use axum::{extract::State, Extension, Json};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

// Re-export RefreshTokenResponse from session module
pub use super::session::RefreshTokenResponse;

// Import hash_token from password module
use super::password::hash_token;

// MFA Verify Request
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub preauth_token: String,
    pub code: String,
    pub device_code_id: Option<String>, // Optional: for device flow MFA completion
}

/// POST /api/auth/mfa/verify - Verify MFA code and complete authentication
#[axum::debug_handler]
pub async fn verify_mfa_login(
    State(state): State<AppState>,
    request_info: Extension<RequestInfo>,
    Json(req): Json<MfaVerifyRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    // Validate pre-auth token
    let claims = state.jwt_service.validate_token(&req.preauth_token)?;

    // Ensure this is a pre-auth token
    if claims.mfa_required != Some(true) {
        return Err(AppError::BadRequest(
            "Invalid pre-authentication token".to_string(),
        ));
    }

    // Verify the MFA code (TOTP or backup code)
    let is_valid =
        crate::handlers::user::verify_mfa_code(&state.db, &claims.sub, &req.code).await?;

    if !is_valid {
        // Add audit logging for failed MFA verification
        let verification_type =
            if req.code.len() == 6 && req.code.chars().all(|c| c.is_ascii_digit()) {
                "totp"
            } else {
                "backup_code"
            };
        // Non-blocking audit via actor
        let event = MfaAuditBuilder::new(&claims.sub, "mfa_verify_failed")
            .org_id(claims.org.as_deref())
            .ip_address(Some(&request_info.ip_address))
            .user_agent(Some(request_info.user_agent.clone()))
            .success(false)
            .details(Some(&format!(
                "method:{},reason:invalid_code",
                verification_type
            )))
            .build();
        state.audit_actor.log_mfa(event).await;

        return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
    }

    // Load user to get updated information
    let db = &state.db;
    let user_id = claims.sub.clone();
    let user_entity = with_deadlock_retry("find_user_details", 10, || {
        let db = db.clone();
        let uid = user_id.clone();
        async move {
            use sea_orm::EntityTrait;
            users::Entity::find_by_id(uid).one(&db).await
        }
    })
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user: User = user_entity.into();

    consume_mfa_preauth_token(&state, &claims).await?;

    // Check if this MFA verification is part of a SAML authentication flow
    if let Some(saml_state_id) = &claims.saml_state {
        let service_id = match (claims.org.as_deref(), claims.service.as_deref()) {
            (Some(org_slug), Some(service_slug)) => {
                let service = ServiceStore::find_by_org_slug_and_service_slug(
                    DB::Conn(&state.db),
                    org_slug,
                    service_slug,
                )
                .await?
                .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
                Some(service.id)
            }
            _ => None,
        };

        // Complete SAML authentication instead of issuing JWT
        // Note: This returns HTML, not JSON, which is appropriate for SAML flows
        return crate::handlers::saml::complete_saml_authentication(
            &state,
            saml_state_id,
            service_id.as_deref(),
            &user,
        )
        .await
        .map(|_html_response| {
            // Convert HTML response to JSON response
            // This is a workaround - ideally SAML flows would use a different endpoint
            // The frontend should handle SAML flows differently
            Json(RefreshTokenResponse {
                access_token: "SAML_COMPLETE".to_string(),
                refresh_token: String::new(),
                expires_in: 0,
            })
        });
    }

    // Generate full session JWT
    let resource = crate::utils::resource_indicators::resource_from_audience(claims.aud.as_deref());
    let resource_owned = resource.map(str::to_string);
    let token = state.jwt_service.create_token_with_resource(
        &user.id,
        &user.email,
        user.is_platform_owner,
        claims.org.as_deref(),
        claims.service.as_deref(),
        resource,
    )?;

    // Create session with refresh token
    let _session_id = Uuid::new_v4().to_string();
    let token_hash = hash_token(&token);
    let refresh_token = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);
    let _created_at = now;

    let org_slug = claims.org.as_deref();
    let service_id: Option<String> = if let Some(service_slug) = claims.service.as_deref() {
        if let Some(org_s) = org_slug {
            ServiceStore::find_by_org_slug_and_service_slug(
                DB::Conn(&state.db),
                org_s,
                service_slug,
            )
            .await?
            .map(|s| s.id)
        } else {
            None
        }
    } else {
        None
    };

    // Create session (use retry for SQLite contention)
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_session_mfa",
        |db| {
            let user_id = user.id.clone();
            let token_hash = token_hash.clone();
            let expires_at = expires_at.naive_utc();
            let refresh_token = refresh_token.clone();
            let refresh_expires_at = refresh_expires_at.naive_utc();
            let org_slug = org_slug.map(|s| s.to_string());
            let service_id = service_id.clone();
            let resource = resource_owned.clone();

            Box::pin(async move {
                SessionStore::create(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    expires_at,
                    Some(&refresh_token),
                    Some(refresh_expires_at),
                    org_slug.as_deref(),
                    service_id.as_deref(),
                    resource.as_deref(),
                    None,
                    None,
                )
                .await
            })
        },
    )
    .await?;

    // If this is for a device flow, authorize the device code now

    if let Some(device_code_id) = req.device_code_id {
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "authorize_device_code",
            |db| {
                let device_code_id = device_code_id.clone();
                let user_id = user.id.clone();
                Box::pin(async move {
                    // Verify the device code belongs to this user and update its status
                    DeviceCodeStore::authorize_for_user(db.clone(), &device_code_id, &user_id).await
                })
            },
        )
        .await?;
    }

    // Add audit logging for successful MFA verification
    let verification_type = if req.code.len() == 6 && req.code.chars().all(|c| c.is_ascii_digit()) {
        "totp"
    } else {
        "backup_code"
    };

    // Use original variables for logging
    let verification_type = verification_type.to_string();

    // Non-blocking audit via actor (no transaction needed - actor handles retries)
    let success_event = MfaAuditBuilder::new(&claims.sub, "mfa_verify_success")
        .org_id(claims.org.as_deref())
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .details(Some(&verification_type))
        .build();
    state.audit_actor.log_mfa(success_event).await;

    // If it's a backup code, log its usage specifically
    if verification_type == "backup_code" {
        let backup_event = MfaAuditBuilder::new(&claims.sub, "backup_code_used")
            .org_id(claims.org.as_deref())
            .ip_address(Some(&request_info.ip_address))
            .user_agent(Some(request_info.user_agent.clone()))
            .success(true)
            .build();
        state.audit_actor.log_mfa(backup_event).await;
    }

    // Publish login success event for webhooks (after MFA verification)
    crate::handlers::auth::oauth::publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        org_slug,
        service_id.as_deref(),
        Some("mfa"),
    )
    .await;

    Ok(Json(RefreshTokenResponse {
        access_token: token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

async fn consume_mfa_preauth_token(state: &AppState, claims: &Claims) -> Result<()> {
    let now = Utc::now().timestamp();
    let ttl_seconds = (claims.exp - now).max(1);
    let lock_key = format!("mfa-preauth:{}", claims.jti);
    let owner_id = format!("user:{}", claims.sub);

    let consumed = DistributedLockStore::try_acquire_lock(
        DB::Conn(&state.db),
        &lock_key,
        &owner_id,
        ttl_seconds,
    )
    .await?;

    if !consumed {
        return Err(AppError::BadRequest(
            "Invalid pre-authentication token".to_string(),
        ));
    }

    Ok(())
}
