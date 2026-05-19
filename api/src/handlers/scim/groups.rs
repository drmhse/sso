use crate::entities::{memberships, organizations, prelude::*};
use crate::error::{AppError, Result};
use crate::middleware::ScimAuth;
use crate::state::AppState;
use crate::store::{memberships::MembershipStore, organizations::OrganizationStore, DB};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Response,
    Json,
};
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;

use super::schemas::*;

#[derive(Debug, Deserialize)]
pub struct ScimListParams {
    #[serde(rename = "startIndex")]
    start_index: Option<u64>,
    count: Option<u64>,
    filter: Option<String>,
}

/// Convert our Organization entity to SCIM Group format
async fn org_to_scim_group(
    db: &sea_orm::DatabaseConnection,
    org: organizations::Model,
    base_url: &str,
) -> Result<ScimGroup> {
    let location = format!("{}/scim/v2/Groups/{}", base_url, org.id);

    // Get members
    let memberships = Memberships::find()
        .filter(memberships::Column::OrgId.eq(&org.id))
        .all(db)
        .await?;

    let members: Vec<ScimGroupMember> = memberships
        .into_iter()
        .map(|m| {
            let user_id = m.user_id.clone();
            ScimGroupMember {
                value: user_id.clone(),
                ref_url: Some(format!("{}/scim/v2/Users/{}", base_url, user_id)),
                member_type: Some("User".to_string()),
            }
        })
        .collect();

    Ok(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.to_string()],
        id: org.id.clone(),
        external_id: None,
        meta: ScimMeta {
            resource_type: "Group".to_string(),
            created: DateTime::<Utc>::from_naive_utc_and_offset(org.created_at, Utc).to_rfc3339(),
            last_modified: DateTime::<Utc>::from_naive_utc_and_offset(org.updated_at, Utc)
                .to_rfc3339(),
            location: Some(location),
        },
        display_name: org.name,
        members: if members.is_empty() {
            None
        } else {
            Some(members)
        },
    })
}

async fn current_scim_org(state: &AppState, scim_auth: &ScimAuth) -> Result<organizations::Model> {
    OrganizationStore::find_by_id(DB::Conn(&state.db), &scim_auth.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))
}

async fn current_scim_org_by_group_id(
    state: &AppState,
    scim_auth: &ScimAuth,
    group_id: &str,
) -> Result<organizations::Model> {
    if group_id != scim_auth.org_id {
        return Err(AppError::NotFound("Group not found".to_string()));
    }

    current_scim_org(state, scim_auth).await
}

async fn ensure_user_belongs_to_scim_org(
    state: &AppState,
    org_id: &str,
    user_id: &str,
) -> Result<()> {
    let user = crate::store::users::UserStore::find_by_id(DB::Conn(&state.db), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if user.org_id.as_deref() != Some(org_id) {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    Ok(())
}

/// List Groups - GET /scim/v2/Groups
pub async fn list_groups(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Query(params): Query<ScimListParams>,
) -> Result<Json<ScimListResponse<ScimGroup>>> {
    let start_index = params.start_index.unwrap_or(1);
    let count = params.count.unwrap_or(100).min(1000);

    let org = current_scim_org(&state, &scim_auth).await?;

    let matches_filter = if let Some(filter) = params.filter {
        // Parse simple filters like: displayName eq "Acme Corp"
        if filter.contains("displayName eq") {
            let name = filter
                .split("displayName eq")
                .nth(1)
                .and_then(|s| s.trim().trim_matches('"').split('"').next())
                .unwrap_or("");

            if !name.is_empty() {
                org.name == name
            } else {
                false
            }
        } else {
            false
        }
    } else {
        true
    };

    let base_url = &state.base_url;
    let include_resource = matches_filter && start_index <= 1 && count > 0;
    let scim_groups = if include_resource {
        vec![org_to_scim_group(&state.db, org, &base_url).await?]
    } else {
        vec![]
    };

    Ok(Json(ScimListResponse::new(
        scim_groups,
        if matches_filter { 1 } else { 0 },
        start_index,
        count,
    )))
}

/// Get Group by ID - GET /scim/v2/Groups/:id
pub async fn get_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
) -> Result<Json<ScimGroup>> {
    let org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    let base_url = &state.base_url;
    let scim_group = org_to_scim_group(&state.db, org, &base_url).await?;

    Ok(Json(scim_group))
}

/// Create Group - POST /scim/v2/Groups
pub async fn create_group(
    State(_state): State<AppState>,
    Extension(_scim_auth): Extension<ScimAuth>,
    Json(_req): Json<ScimGroupRequest>,
) -> Result<Response> {
    Err(AppError::Forbidden(
        "SCIM group creation is not supported for organization-scoped tokens".to_string(),
    ))
}

/// Update Group (PUT) - PUT /scim/v2/Groups/:id
pub async fn update_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
    Json(req): Json<ScimGroupRequest>,
) -> Result<Json<ScimGroup>> {
    let org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    // Note: Organization name updates would need to be implemented in OrganizationStore
    // For now, we'll skip this as it's not a critical SCIM feature

    // Update members if provided
    if let Some(members) = req.members {
        // Get current members
        let current_members =
            MembershipStore::list_by_org(DB::Conn(&state.db), &org.id, None, 1000, 0).await?;
        let current_user_ids: Vec<String> =
            current_members.iter().map(|m| m.user_id.clone()).collect();

        // Add new members
        for member in &members {
            if !current_user_ids.contains(&member.value) {
                ensure_user_belongs_to_scim_org(&state, &org.id, &member.value).await?;

                // Add member with default role "member"
                MembershipStore::create(DB::Conn(&state.db), &org.id, &member.value, "member")
                    .await?;

                // Grant permission
                use crate::entities::permissions::RelationTuple;
                use crate::store::permissions::PermissionsStore;
                PermissionsStore::grant(
                    DB::Conn(&state.db),
                    RelationTuple::user(
                        "organization".to_string(),
                        org.id.clone(),
                        "member".to_string(),
                        member.value.clone(),
                    ),
                )
                .await?;
            }
        }

        // Remove members not in the new list
        let new_user_ids: Vec<String> = members.iter().map(|m| m.value.clone()).collect();
        for current_member in current_members {
            if !new_user_ids.contains(&current_member.user_id) {
                MembershipStore::delete(DB::Conn(&state.db), &current_member.id).await?;

                // Revoke permission
                use crate::entities::permissions::SUBJECT_TYPE_USER;
                use crate::store::permissions::PermissionsStore;
                PermissionsStore::revoke(
                    DB::Conn(&state.db),
                    "organization",
                    &org.id,
                    &current_member.role,
                    SUBJECT_TYPE_USER,
                    &current_member.user_id,
                    None,
                )
                .await?;
            }
        }
    }

    let updated_org = OrganizationStore::find_by_id(DB::Conn(&state.db), &group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let base_url = &state.base_url;
    let scim_group = org_to_scim_group(&state.db, updated_org, &base_url).await?;

    Ok(Json(scim_group))
}

/// Patch Group (PATCH) - PATCH /scim/v2/Groups/:id
pub async fn patch_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
    Json(req): Json<ScimPatchRequest>,
) -> Result<Json<ScimGroup>> {
    let org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    // Process each operation
    for op in req.operations {
        match op.op.to_lowercase().as_str() {
            "add" => {
                // Add members
                if let Some(value) = op.value {
                    if let Some(members_array) = value.get("members") {
                        if let Some(members) = members_array.as_array() {
                            for member_value in members {
                                if let Some(user_id) =
                                    member_value.get("value").and_then(|v| v.as_str())
                                {
                                    ensure_user_belongs_to_scim_org(&state, &org.id, user_id)
                                        .await?;

                                    // Add member
                                    MembershipStore::create(
                                        DB::Conn(&state.db),
                                        &org.id,
                                        user_id,
                                        "member",
                                    )
                                    .await?;

                                    // Grant permission
                                    use crate::entities::permissions::RelationTuple;
                                    use crate::store::permissions::PermissionsStore;
                                    PermissionsStore::grant(
                                        DB::Conn(&state.db),
                                        RelationTuple::user(
                                            "organization".to_string(),
                                            org.id.clone(),
                                            "member".to_string(),
                                            user_id.to_string(),
                                        ),
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                }
            }
            "remove" => {
                // Remove members
                if let Some(path) = op.path {
                    if path.starts_with("members[value eq") {
                        // Extract user_id from path: members[value eq "user-id"]
                        if let Some(user_id) = path
                            .split("members[value eq \"")
                            .nth(1)
                            .and_then(|s| s.split("\"]").next())
                        {
                            // Find and delete membership
                            let membership = MembershipStore::find_by_org_and_user(
                                DB::Conn(&state.db),
                                &org.id,
                                user_id,
                            )
                            .await?;

                            if let Some(m) = membership {
                                MembershipStore::delete(DB::Conn(&state.db), &m.id).await?;

                                // Revoke permission
                                use crate::entities::permissions::SUBJECT_TYPE_USER;
                                use crate::store::permissions::PermissionsStore;
                                PermissionsStore::revoke(
                                    DB::Conn(&state.db),
                                    "organization",
                                    &org.id,
                                    &m.role,
                                    SUBJECT_TYPE_USER,
                                    user_id,
                                    None,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }
            _ => {
                // Ignore other operations
            }
        }
    }

    let updated_org = OrganizationStore::find_by_id(DB::Conn(&state.db), &group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let base_url = &state.base_url;
    let scim_group = org_to_scim_group(&state.db, updated_org, &base_url).await?;

    Ok(Json(scim_group))
}

/// Delete Group - DELETE /scim/v2/Groups/:id
pub async fn delete_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
) -> Result<StatusCode> {
    // For now, return an error as we don't want SCIM to delete organizations
    let _org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    Err(AppError::Forbidden(
        "Group deletion via SCIM is not supported. Please use the Organizations API.".to_string(),
    ))
}
