use crate::db::models::User;
use crate::entities::{user_totp_secrets, users};
use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{totp::TotpStore, users::UserStore, DB};
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{create_audit_log, user_model_to_old};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PromoteOwnerRequest {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    pub q: String, // Search query (email or user ID)
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserSearchResult {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UserListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserSearchResult>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    pub enabled: bool,
    pub has_backup_codes: bool,
}

// ============================================================================
// User Management Endpoints
// ============================================================================

/// GET /api/platform/users/:user_id - Get a single user by ID
pub async fn get_platform_user(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<UserSearchResult>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserSearchResult {
        id: user.id,
        email: user.email,
        is_platform_owner: user.is_platform_owner,
        created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(user.created_at, Utc)
            .to_rfc3339(),
    }))
}

/// GET /api/platform/users - List all users with pagination
pub async fn list_users(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(params): Query<UserListParams>,
) -> Result<Json<UserListResponse>> {
    // Only platform owners can list users
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let limit_val = params.limit.unwrap_or(50).min(100); // Cap at 100 results
    let offset_val = params.offset.unwrap_or(0).max(0);

    // Get users using store
    let users =
        UserStore::list_all(DB::Conn(&state.db), limit_val as u64, offset_val as u64).await?;
    let total = UserStore::count_all(DB::Conn(&state.db), false).await? as i64;

    // Convert to response format
    let user_results = users
        .into_iter()
        .map(|u| UserSearchResult {
            id: u.id,
            email: u.email,
            is_platform_owner: u.is_platform_owner,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(u.created_at, Utc)
                .to_rfc3339(),
        })
        .collect();

    Ok(Json(UserListResponse {
        users: user_results,
        total,
    }))
}

/// GET /api/platform/users/search - Search users by email or ID
pub async fn search_users(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(query): Query<UserSearchQuery>,
) -> Result<Json<Vec<UserSearchResult>>> {
    // Only platform owners can search users
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let limit_val = query.limit.unwrap_or(10).min(50); // Cap at 50 results

    // Search users using store with relevance-based ordering
    let store_results =
        UserStore::search_with_relevance(DB::Conn(&state.db), &query.q, limit_val as u64).await?;

    // Convert store results to handler results
    let results = store_results
        .into_iter()
        .map(|r| UserSearchResult {
            id: r.id,
            email: r.email,
            is_platform_owner: r.is_platform_owner,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(r.created_at, Utc)
                .to_rfc3339(),
        })
        .collect();

    Ok(Json(results))
}

/// POST /api/platform/owners
/// Promote a user to platform owner
pub async fn promote_platform_owner(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<PromoteOwnerRequest>,
) -> Result<Json<User>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = req.user_id.clone();
    let owner_id = auth_user.user.id.clone();

    let updated_user = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "promote_platform_owner",
        |db| {
            let user_id = user_id.clone();
            let owner_id = owner_id.clone();
            Box::pin(async move {
                // Fetch user
                let user_model = UserStore::find_by_id(db.clone(), &user_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

                if user_model.is_platform_owner {
                    return Err(AppError::BadRequest(
                        "User is already a platform owner".to_string(),
                    ));
                }

                // Update user
                let mut user_active: users::ActiveModel = user_model.into();
                user_active.is_platform_owner = Set(true);

                let updated_user_model = user_active.update(&db).await?;
                let updated_user = user_model_to_old(updated_user_model.clone());

                // Create audit log
                create_audit_log(
                    &db,
                    &owner_id,
                    "promote_platform_owner",
                    "user",
                    &user_id,
                    Some(json!({
                        "user_email": updated_user_model.email,
                    })),
                )
                .await?;

                Ok(updated_user)
            })
        },
    )
    .await?;

    Ok(Json(updated_user))
}

/// DELETE /api/platform/owners/:user_id
/// Demote a platform owner to regular user
pub async fn demote_platform_owner(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<User>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Prevent self-demotion
    if auth_user.user.id == user_id {
        return Err(AppError::BadRequest("Cannot demote yourself".to_string()));
    }

    let owner_id = auth_user.user.id.clone();

    let updated_user = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "demote_platform_owner",
        |db| {
            let user_id = user_id.clone();
            let owner_id = owner_id.clone();
            Box::pin(async move {
                // Fetch user to demote
                let user_model = UserStore::find_by_id(db.clone(), &user_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

                if !user_model.is_platform_owner {
                    return Err(AppError::BadRequest(
                        "User is not a platform owner".to_string(),
                    ));
                }

                // Check if this is the last platform owner
                // Check if we can demote this user (must have at least one other platform owner)
                let owner_count = UserStore::count_platform_owners(db.clone()).await? as i64;

                if owner_count <= 1 {
                    return Err(AppError::BadRequest(
                        "Cannot demote the last platform owner".to_string(),
                    ));
                }

                // Update user
                let mut user_active: users::ActiveModel = user_model.into();
                user_active.is_platform_owner = Set(false);

                let updated_user_model = user_active.update(&db).await?;
                let updated_user = user_model_to_old(updated_user_model.clone());

                // Create audit log
                create_audit_log(
                    &db,
                    &owner_id,
                    "demote_platform_owner",
                    "user",
                    &user_id,
                    Some(json!({
                        "user_email": updated_user_model.email,
                    })),
                )
                .await?;

                Ok(updated_user)
            })
        },
    )
    .await?;

    Ok(Json(updated_user))
}

/// GET /api/platform/users/:user_id/mfa/status
/// Get MFA status for a user (Platform Owner only)
pub async fn get_user_mfa_status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<MfaStatusResponse>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Check if user exists
    let _user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check MFA status
    let totp_secret = user_totp_secrets::Entity::find()
        .filter(user_totp_secrets::Column::UserId.eq(&user_id))
        .one(&state.db)
        .await?;

    let mfa_enabled = totp_secret.as_ref().map(|t| t.enabled).unwrap_or(false);

    // Check for backup codes (checking any codes, not just unused)
    let has_backup_codes = if mfa_enabled {
        let count = TotpStore::count_backup_codes(DB::Conn(&state.db), &user_id).await?;
        count > 0
    } else {
        false
    };

    Ok(Json(MfaStatusResponse {
        enabled: mfa_enabled,
        has_backup_codes,
    }))
}

/// DELETE /api/platform/users/:user_id/mfa
/// Force disable MFA for a user (Platform Owner only)
pub async fn force_disable_user_mfa(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Check if user exists
    let user_model = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Delete TOTP secret and backup codes using TotpStore
    TotpStore::delete_totp_secret(DB::Conn(&state.db), &user_id).await?;
    TotpStore::delete_backup_codes(DB::Conn(&state.db), &user_id).await?;

    // Create audit log
    create_audit_log(
        &state.db,
        &auth_user.user.id,
        "force_disable_mfa",
        "user",
        &user_id,
        Some(json!({
            "user_email": user_model.email,
            "admin_id": auth_user.user.id,
            "admin_email": auth_user.user.email,
        })),
    )
    .await?;

    Ok(Json(json!({
        "success": true,
        "message": "MFA has been force-disabled for the user"
    })))
}
