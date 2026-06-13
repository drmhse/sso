use crate::entities::permissions::{RelationTuple, SUBJECT_TYPE_USER};
use crate::entities::{prelude::Users, users};
use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::ScimAuth;
use crate::services::job_queue::JobQueueService;
use crate::services::scim_filter::{ScimFilterParser, ScimOperator};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, permissions::PermissionsStore, users::UserStore, DB,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use super::schemas::*;

#[derive(Debug, Deserialize)]
pub struct ScimListParams {
    #[serde(rename = "startIndex")]
    start_index: Option<u64>,
    count: Option<u64>,
    filter: Option<String>,
}

/// Convert our User entity to SCIM User format
fn user_to_scim(user: users::Model, base_url: &str) -> ScimUser {
    let location = format!("{}/scim/v2/Users/{}", base_url, user.id);

    ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.to_string()],
        id: user.id.clone(),
        external_id: None,
        meta: ScimMeta {
            resource_type: "User".to_string(),
            created: DateTime::<Utc>::from_naive_utc_and_offset(user.created_at, Utc).to_rfc3339(),
            last_modified: DateTime::<Utc>::from_naive_utc_and_offset(
                user.updated_at.unwrap_or(user.created_at),
                Utc,
            )
            .to_rfc3339(),
            location: Some(location),
        },
        user_name: user.email.clone(),
        name: Some(ScimName {
            formatted: Some(user.email.clone()),
            family_name: None,
            given_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
        }),
        display_name: Some(user.email.clone()),
        emails: Some(vec![ScimEmail {
            value: user.email.clone(),
            email_type: Some("work".to_string()),
            primary: Some(true),
        }]),
        active: user.deleted_at.is_none(), // Active if not soft-deleted
    }
}

fn ensure_scim_can_deprovision_membership(
    membership: &crate::entities::memberships::Model,
) -> Result<()> {
    if matches!(membership.role.as_str(), "owner" | "admin") {
        return Err(AppError::Forbidden(
            "SCIM cannot deprovision organization owners or admins".to_string(),
        ));
    }

    Ok(())
}

async fn scoped_email_conflict(
    state: &AppState,
    org_id: &str,
    email: &str,
    current_user_id: Option<&str>,
) -> Result<bool> {
    let existing =
        UserStore::find_by_email_with_context(DB::Conn(&state.db), email, Some(org_id)).await?;

    Ok(existing
        .map(|user| current_user_id.map(|id| user.id != id).unwrap_or(true))
        .unwrap_or(false))
}

/// List Users - GET /scim/v2/Users
pub async fn list_users(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Query(params): Query<ScimListParams>,
) -> Result<Json<ScimListResponse<ScimUser>>> {
    let start_index = params.start_index.unwrap_or(1);
    let count = params.count.unwrap_or(100).min(1000); // Max 1000 per page

    // Get user IDs that are members of this organization
    use crate::entities::{memberships, prelude::Memberships};
    let member_user_ids = Memberships::find()
        .filter(memberships::Column::OrgId.eq(&scim_auth.org_id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|m| m.user_id)
        .collect::<Vec<_>>();

    let offset = if start_index > 0 { start_index - 1 } else { 0 };

    // Handle filters (SCIM 2.0 filtering)
    let users = if let Some(filter) = params.filter {
        // Parse SCIM filter using proper parser
        match ScimFilterParser::parse(&filter) {
            Ok(expressions) => {
                let mut query =
                    Users::find().filter(users::Column::Id.is_in(member_user_ids.clone()));
                for expr in expressions {
                    query = match expr.attribute_path.as_str() {
                        "userName" | "email" => {
                            if let Some(ref value) = expr.comparison_value {
                                match expr.operator {
                                    ScimOperator::Equals => {
                                        query = query.filter(users::Column::Email.eq(value))
                                    }
                                    ScimOperator::Contains => {
                                        query = query.filter(users::Column::Email.contains(value))
                                    }
                                    ScimOperator::StartsWith => {
                                        query =
                                            query.filter(users::Column::Email.starts_with(value))
                                    }
                                    ScimOperator::EndsWith => {
                                        query = query.filter(users::Column::Email.ends_with(value))
                                    }
                                    ScimOperator::NotEquals => {
                                        query = query.filter(users::Column::Email.ne(value))
                                    }
                                    _ => {
                                        tracing::debug!(
                                            "Unsupported operator {} for userName filter",
                                            expr.operator.as_str()
                                        );
                                    }
                                }
                            } else {
                                tracing::debug!("userName filter requires comparison value");
                            }
                            query
                        }
                        // Note: "active" attribute is not supported in the current users table schema
                        _ => {
                            tracing::debug!("Unsupported attribute path: {}", expr.attribute_path);
                            query
                        }
                    };
                }
                query.all(&state.db).await?
            }
            Err(e) => {
                tracing::debug!("Failed to parse SCIM filter '{}': {}", filter, e);
                vec![] // Return empty results for invalid filters
            }
        }
    } else {
        // No filter - return organization members (paginated)
        Users::find()
            .filter(users::Column::Id.is_in(member_user_ids.clone()))
            .paginate(&state.db, count)
            .fetch_page(offset / count.max(1))
            .await?
    };

    let total_results = Users::find()
        .filter(users::Column::Id.is_in(member_user_ids))
        .count(&state.db)
        .await?;

    let base_url = &state.base_url;
    let scim_users: Vec<ScimUser> = users
        .into_iter()
        .map(|u| user_to_scim(u, &base_url))
        .collect();

    Ok(Json(ScimListResponse::new(
        scim_users,
        total_results,
        start_index,
        count,
    )))
}

/// Get User by ID - GET /scim/v2/Users/:id
pub async fn get_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
) -> Result<Response> {
    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id).await?;

    // If user doesn't exist, return SCIM not found error
    let user = match user {
        Some(u) => u,
        None => {
            let error = ScimError::not_found("User not found".to_string());
            return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
        }
    };

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    if membership.is_none() {
        // User exists but not in this organization - return 404 for security (don't leak user existence)
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    }

    let base_url = &state.base_url;
    Ok(Json(user_to_scim(user, &base_url)).into_response())
}

/// Create User - POST /scim/v2/Users
pub async fn create_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    ScimJson(req): ScimJson<ScimUserRequest>,
) -> Result<Response> {
    // Extract email from request
    let email = if let Some(emails) = &req.emails {
        emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or(req.user_name.clone())
    } else {
        req.user_name.clone()
    };

    // Check if user already exists in this SCIM token's organization.
    if scoped_email_conflict(&state, &scim_auth.org_id, &email, None).await? {
        let error = ScimError::uniqueness(format!("User with email {} already exists", email));
        return Ok((StatusCode::CONFLICT, Json(error)).into_response());
    }

    // Clone values needed in the closure for retrying transaction
    let email_clone = email.clone();
    let org_id_clone = scim_auth.org_id.clone();

    // Use retrying transaction for atomicity with automatic retry on contention
    let created_user = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "scim_create_user",
        |db| {
            let email = email_clone.clone();
            let org_id = org_id_clone.clone();

            Box::pin(async move {
                // Create user
                let user = users::ActiveModel {
                    id: Set(Uuid::new_v4().to_string()),
                    email: Set(email.to_lowercase()),
                    org_id: Set(Some(org_id.clone())),
                    password_hash: Set(None),
                    is_platform_owner: Set(false),
                    email_verified_at: Set(None),
                    created_at: Set(Utc::now().naive_utc()),
                    updated_at: Set(None),
                    deleted_at: Set(None),
                };

                let created_user = user.insert(&db).await?;

                // Create membership in organization with 'member' role
                MembershipStore::create(db.clone(), &org_id, &created_user.id, "member").await?;

                // Grant member permission in the permissions table
                PermissionsStore::grant(
                    db.clone(),
                    RelationTuple {
                        namespace: "organization".to_string(),
                        object_id: org_id.clone(),
                        relation: "member".to_string(),
                        subject_type: SUBJECT_TYPE_USER.to_string(),
                        subject_id: created_user.id.clone(),
                        subject_relation: None,
                    },
                )
                .await?;

                // Enqueue welcome email job using the proper email job type
                JobQueueService::enqueue_email(
                    db.clone(),
                    &created_user.email,
                    "Welcome!",
                    &format!("Welcome to the platform, {}!", created_user.email),
                    None,
                )
                .await?;

                Ok(created_user)
            })
        },
    )
    .await?;

    tracing::debug!(
        user_id = %created_user.id,
        org_id = %scim_auth.org_id,
        "SCIM user provisioned with membership and welcome email queued"
    );

    let base_url = &state.base_url;
    let scim_user = user_to_scim(created_user, &base_url);

    Ok((StatusCode::CREATED, Json(scim_user)).into_response())
}

/// Update User (PUT) - PUT /scim/v2/Users/:id
pub async fn update_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
    ScimJson(req): ScimJson<ScimUserRequest>,
) -> Result<Response> {
    if let Some(error) = scim_id_mismatch_error(&user_id, req.id.as_deref(), "User") {
        return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
    }

    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    if membership.is_none() {
        // User exists but not in this organization - return 404 for security
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    }

    // Extract email from request
    let email = if let Some(emails) = &req.emails {
        emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or(req.user_name.clone())
    } else {
        req.user_name.clone()
    };

    if scoped_email_conflict(&state, &scim_auth.org_id, &email, Some(&user.id)).await? {
        let error = ScimError::uniqueness(format!("User with email {} already exists", email));
        return Ok((StatusCode::CONFLICT, Json(error)).into_response());
    }

    let mut active_user: users::ActiveModel = user.into();
    active_user.email = Set(email.to_lowercase());
    active_user.updated_at = Set(Some(Utc::now().naive_utc()));

    let updated_user = active_user.update(&state.db).await?;

    // Note: The users table doesn't store name fields (givenName, familyName)
    // These are provided in SCIM requests but not persisted to the database
    // The user_to_scim function will return None for these fields
    let base_url = &state.base_url;
    Ok(Json(user_to_scim(updated_user, &base_url)).into_response())
}

/// Patch User (PATCH) - PATCH /scim/v2/Users/:id
pub async fn patch_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
    Json(req): Json<ScimPatchRequest>,
) -> Result<Response> {
    if let Some(error) = scim_patch_schema_error(&req.schemas) {
        return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
    }

    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    let membership = if let Some(membership) = membership {
        membership
    } else {
        // User exists but not in this organization - return 404 for security
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    };

    let current_user_id = user.id.clone();
    let mut active_user: users::ActiveModel = user.into();

    // Process each operation
    for op in req.operations {
        match op.op.to_lowercase().as_str() {
            "replace" => {
                // Handle updates based on path
                if let Some(path) = op.path {
                    if path == "emails" || path == "userName" {
                        // Handle email updates
                        if let Some(value) = op.value {
                            if let Some(email_str) = value.as_str() {
                                if scoped_email_conflict(
                                    &state,
                                    &scim_auth.org_id,
                                    email_str,
                                    Some(&current_user_id),
                                )
                                .await?
                                {
                                    let error = ScimError::uniqueness(format!(
                                        "User with email {} already exists",
                                        email_str
                                    ));
                                    return Ok((StatusCode::CONFLICT, Json(error)).into_response());
                                }
                                active_user.email = Set(email_str.to_lowercase());
                            } else if let Some(emails_arr) = value.as_array() {
                                if let Some(first_email) = emails_arr.first() {
                                    if let Some(email_val) =
                                        first_email.get("value").and_then(|v| v.as_str())
                                    {
                                        if scoped_email_conflict(
                                            &state,
                                            &scim_auth.org_id,
                                            email_val,
                                            Some(&current_user_id),
                                        )
                                        .await?
                                        {
                                            let error = ScimError::uniqueness(format!(
                                                "User with email {} already exists",
                                                email_val
                                            ));
                                            return Ok(
                                                (StatusCode::CONFLICT, Json(error)).into_response()
                                            );
                                        }
                                        active_user.email = Set(email_val.to_lowercase());
                                    }
                                }
                            }
                        }
                    } else if path == "active" {
                        // Handle active/disabled state updates
                        if let Some(value) = op.value {
                            if let Some(is_active) = value.as_bool() {
                                if is_active {
                                    // Set active: clear deleted_at timestamp
                                    active_user.deleted_at = Set(None);
                                } else {
                                    ensure_scim_can_deprovision_membership(&membership)?;
                                    // Set disabled: set deleted_at timestamp
                                    active_user.deleted_at = Set(Some(Utc::now().naive_utc()));
                                }
                                // Update updated_at timestamp
                                active_user.updated_at = Set(Some(Utc::now().naive_utc()));
                            }
                        }
                    }
                }
            }
            _ => {
                // Ignore unsupported operations
            }
        }
    }

    let updated_user = active_user.update(&state.db).await?;

    let base_url = &state.base_url;
    Ok(Json(user_to_scim(updated_user, &base_url)).into_response())
}

/// Delete User - DELETE /scim/v2/Users/:id
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
) -> Result<Response> {
    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    let membership = if let Some(membership) = membership {
        membership
    } else {
        // User exists but not in this organization - return 404 for security
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    };

    ensure_scim_can_deprovision_membership(&membership)?;

    MembershipStore::delete(DB::Conn(&state.db), &membership.id).await?;
    PermissionsStore::revoke(
        DB::Conn(&state.db),
        "organization",
        &scim_auth.org_id,
        &membership.role,
        SUBJECT_TYPE_USER,
        &user.id,
        None,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
