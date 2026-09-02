use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{memberships, organizations, permissions::SUBJECT_TYPE_USER, prelude::*};
use crate::error::{AppError, Result};
use crate::middleware::ScimAuth;
use crate::services::scim_filter::{ScimFilterParser, ScimOperator};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore, permissions::PermissionsStore,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

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
            let user_id = m.user_id;
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

fn ensure_scim_can_remove_membership(membership: &memberships::Model) -> Result<()> {
    if matches!(membership.role.as_str(), "owner" | "admin") {
        return Err(AppError::Forbidden(
            "SCIM cannot remove organization owners or admins".to_string(),
        ));
    }

    Ok(())
}

fn group_matches_filter(display_name: &str, filter: &str) -> std::result::Result<bool, ScimError> {
    let expressions = ScimFilterParser::parse(filter)
        .map_err(|error| ScimError::invalid_filter(error.to_string()))?;
    if expressions.is_empty() {
        return Err(ScimError::invalid_filter(
            "Filter expression cannot be empty".to_string(),
        ));
    }

    expressions
        .into_iter()
        .try_fold(true, |matches, expression| {
            if expression.attribute_path != "displayName" {
                return Err(ScimError::invalid_filter(format!(
                    "Unsupported group filter attribute: {}",
                    expression.attribute_path
                )));
            }
            let value = expression.comparison_value.ok_or_else(|| {
                ScimError::invalid_filter("displayName requires a comparison value".to_string())
            })?;
            if value.is_empty() {
                return Err(ScimError::invalid_filter(
                    "displayName comparison value cannot be empty".to_string(),
                ));
            }

            let expression_matches = match expression.operator {
                ScimOperator::Equals => display_name == value,
                ScimOperator::NotEquals => display_name != value,
                ScimOperator::Contains => display_name.contains(&value),
                ScimOperator::StartsWith => display_name.starts_with(&value),
                ScimOperator::EndsWith => display_name.ends_with(&value),
                operator => {
                    return Err(ScimError::invalid_filter(format!(
                        "Operator {} is not supported for displayName",
                        operator.as_str()
                    )))
                }
            };

            Ok(matches && expression_matches)
        })
}

#[derive(Clone)]
enum GroupPatchAction {
    Add(Vec<String>),
    Remove(String),
}

fn parse_group_patch_operations(
    operations: Vec<ScimPatchOp>,
) -> std::result::Result<Vec<GroupPatchAction>, ScimError> {
    if operations.is_empty() {
        return Err(ScimError::invalid_value(
            "PATCH request must contain at least one operation".to_string(),
        ));
    }

    operations
        .into_iter()
        .map(
            |operation| match operation.op.to_ascii_lowercase().as_str() {
                "add" => {
                    let value = operation.value.ok_or_else(|| {
                        ScimError::invalid_value("Group add operation requires a value".to_string())
                    })?;
                    let members = match operation.path.as_deref() {
                        None => value.get("members").and_then(|members| members.as_array()),
                        Some("members") => value.as_array(),
                        Some(path) => {
                            return Err(ScimError::invalid_value(format!(
                                "Unsupported group add path: {path}"
                            )))
                        }
                    }
                    .ok_or_else(|| {
                        ScimError::invalid_value(
                            "Group add value must contain a members array".to_string(),
                        )
                    })?;

                    let user_ids = members
                        .iter()
                        .map(|member| {
                            member
                                .get("value")
                                .and_then(|value| value.as_str())
                                .filter(|value| !value.is_empty())
                                .map(ToString::to_string)
                                .ok_or_else(|| {
                                    ScimError::invalid_value(
                                        "Every group member must have a non-empty value"
                                            .to_string(),
                                    )
                                })
                        })
                        .collect::<std::result::Result<HashSet<_>, _>>()?
                        .into_iter()
                        .collect();
                    Ok(GroupPatchAction::Add(user_ids))
                }
                "remove" => {
                    let path = operation.path.ok_or_else(|| {
                        ScimError::invalid_value(
                            "Group remove operation requires a path".to_string(),
                        )
                    })?;
                    let user_id = path
                        .strip_prefix("members[value eq \"")
                        .and_then(|path| path.strip_suffix("\"]"))
                        .filter(|user_id| !user_id.is_empty())
                        .ok_or_else(|| {
                            ScimError::invalid_value(format!(
                                "Unsupported group remove path: {path}"
                            ))
                        })?;
                    Ok(GroupPatchAction::Remove(user_id.to_string()))
                }
                _ => Err(ScimError::invalid_value(format!(
                    "Unsupported group PATCH operation: {}",
                    operation.op
                ))),
            },
        )
        .collect()
}

/// List Groups - GET /scim/v2/Groups
pub async fn list_groups(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Query(params): Query<ScimListParams>,
) -> Result<Response> {
    let start_index = params.start_index.unwrap_or(1).max(1);
    let count = params.count.unwrap_or(100).min(1000);

    let org = current_scim_org(&state, &scim_auth).await?;

    let matches_filter = if let Some(filter) = params.filter {
        match group_matches_filter(&org.name, &filter) {
            Ok(matches_filter) => matches_filter,
            Err(error) => {
                return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
            }
        }
    } else {
        true
    };

    let base_url = &state.base_url;
    let include_resource = matches_filter && start_index <= 1 && count > 0;
    let scim_groups = if include_resource {
        vec![org_to_scim_group(&state.db, org, base_url).await?]
    } else {
        vec![]
    };

    Ok(Json(ScimListResponse::new(
        scim_groups,
        if matches_filter { 1 } else { 0 },
        start_index,
    ))
    .into_response())
}

/// Get Group by ID - GET /scim/v2/Groups/:id
pub async fn get_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
) -> Result<Json<ScimGroup>> {
    let org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    let base_url = &state.base_url;
    let scim_group = org_to_scim_group(&state.db, org, base_url).await?;

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
) -> Result<Response> {
    if let Some(error) = scim_id_mismatch_error(&group_id, req.id.as_deref(), "Group") {
        return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
    }

    let org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    // Group displayName maps to the organization name, which SCIM cannot rename
    // here: the store has no rename path and tenants are keyed by slug.

    // Update members if provided
    if let Some(members) = req.members {
        let current_members =
            MembershipStore::list_by_org(DB::Conn(&state.db), &org.id, None, 1000, 0).await?;
        let current_user_ids = current_members
            .iter()
            .map(|m| m.user_id.clone())
            .collect::<HashSet<_>>();
        let requested_user_ids = members
            .iter()
            .map(|member| member.value.clone())
            .collect::<HashSet<_>>();
        let add_user_ids = requested_user_ids
            .difference(&current_user_ids)
            .cloned()
            .collect::<Vec<_>>();

        if !add_user_ids.is_empty() {
            let users =
                crate::store::users::UserStore::find_by_ids(DB::Conn(&state.db), &add_user_ids)
                    .await?;
            let users_by_id = users
                .into_iter()
                .map(|user| (user.id.clone(), user))
                .collect::<HashMap<_, _>>();
            for user_id in &add_user_ids {
                let user = users_by_id
                    .get(user_id)
                    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
                if user.org_id.as_deref() != Some(&org.id) {
                    return Err(AppError::NotFound("User not found".to_string()));
                }
            }
        }

        // Validate every removal before making any membership change.
        let remove_members = current_members
            .into_iter()
            .filter(|member| !requested_user_ids.contains(&member.user_id))
            .collect::<Vec<_>>();
        for member in &remove_members {
            ensure_scim_can_remove_membership(member)?;
        }
        let remove_membership_ids = remove_members
            .iter()
            .map(|member| member.id.clone())
            .collect::<Vec<_>>();
        let remove_user_ids = remove_members
            .iter()
            .map(|member| member.user_id.clone())
            .collect::<Vec<_>>();
        let remove_roles = remove_members
            .iter()
            .map(|member| member.role.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let org_id = org.id.clone();

        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "scim_replace_group_members",
            |db| {
                let add_user_ids = add_user_ids.clone();
                let remove_membership_ids = remove_membership_ids.clone();
                let remove_user_ids = remove_user_ids.clone();
                let remove_roles = remove_roles.clone();
                let org_id = org_id.clone();
                Box::pin(async move {
                    use crate::entities::permissions::RelationTuple;

                    let mut grant_tuples = Vec::with_capacity(add_user_ids.len());
                    for user_id in add_user_ids {
                        MembershipStore::create(db.clone(), &org_id, &user_id, "member").await?;
                        grant_tuples.push(RelationTuple::user(
                            "organization".to_string(),
                            org_id.clone(),
                            "member".to_string(),
                            user_id,
                        ));
                    }
                    PermissionsStore::grant_many(db.clone(), grant_tuples).await?;

                    MembershipStore::delete_by_ids(db.clone(), &remove_membership_ids).await?;
                    PermissionsStore::revoke_direct_org_memberships_for_users(
                        db,
                        &org_id,
                        &remove_user_ids,
                        &remove_roles,
                    )
                    .await?;
                    Ok(())
                })
            },
        )
        .await?;
    }

    let updated_org = OrganizationStore::find_by_id(DB::Conn(&state.db), &group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let base_url = &state.base_url;
    let scim_group = org_to_scim_group(&state.db, updated_org, base_url).await?;

    Ok(Json(scim_group).into_response())
}

/// Patch Group (PATCH) - PATCH /scim/v2/Groups/:id
pub async fn patch_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
    Json(req): Json<ScimPatchRequest>,
) -> Result<Response> {
    if let Some(error) = scim_patch_schema_error(&req.schemas) {
        return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
    }

    let org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    let actions = match parse_group_patch_operations(req.operations) {
        Ok(actions) => actions,
        Err(error) => return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response()),
    };

    let current_members =
        MembershipStore::list_by_org(DB::Conn(&state.db), &org.id, None, 1000, 0).await?;
    let current_user_ids = current_members
        .iter()
        .map(|membership| membership.user_id.clone())
        .collect::<HashSet<_>>();
    let requested_add_user_ids = actions
        .iter()
        .filter_map(|action| match action {
            GroupPatchAction::Add(user_ids) => Some(user_ids.iter()),
            GroupPatchAction::Remove(_) => None,
        })
        .flatten()
        .filter(|user_id| !current_user_ids.contains(*user_id))
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if !requested_add_user_ids.is_empty() {
        let users = crate::store::users::UserStore::find_by_ids(
            DB::Conn(&state.db),
            &requested_add_user_ids,
        )
        .await?;
        let users_by_id = users
            .into_iter()
            .map(|user| (user.id.clone(), user))
            .collect::<HashMap<_, _>>();
        for user_id in &requested_add_user_ids {
            let user = users_by_id
                .get(user_id)
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
            if user.org_id.as_deref() != Some(&org.id) {
                return Err(AppError::NotFound("User not found".to_string()));
            }
        }
    }

    for user_id in actions.iter().filter_map(|action| match action {
        GroupPatchAction::Remove(user_id) => Some(user_id),
        GroupPatchAction::Add(_) => None,
    }) {
        if let Some(membership) = current_members
            .iter()
            .find(|membership| membership.user_id == *user_id)
        {
            ensure_scim_can_remove_membership(membership)?;
        }
    }

    let org_id = org.id.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "scim_patch_group_members",
        |db| {
            let actions = actions.clone();
            let org_id = org_id.clone();
            Box::pin(async move {
                use crate::entities::permissions::RelationTuple;

                for action in actions {
                    match action {
                        GroupPatchAction::Add(user_ids) => {
                            let mut grant_tuples = Vec::with_capacity(user_ids.len());
                            for user_id in user_ids {
                                MembershipStore::create(db.clone(), &org_id, &user_id, "member")
                                    .await?;
                                grant_tuples.push(RelationTuple::user(
                                    "organization".to_string(),
                                    org_id.clone(),
                                    "member".to_string(),
                                    user_id,
                                ));
                            }
                            PermissionsStore::grant_many(db.clone(), grant_tuples).await?;
                        }
                        GroupPatchAction::Remove(user_id) => {
                            let membership = MembershipStore::find_by_org_and_user(
                                db.clone(),
                                &org_id,
                                &user_id,
                            )
                            .await?;
                            if let Some(membership) = membership {
                                ensure_scim_can_remove_membership(&membership)?;
                                MembershipStore::delete(db.clone(), &membership.id).await?;
                                PermissionsStore::revoke(
                                    db.clone(),
                                    "organization",
                                    &org_id,
                                    &membership.role,
                                    SUBJECT_TYPE_USER,
                                    &user_id,
                                    None,
                                )
                                .await?;
                            }
                        }
                    }
                }
                Ok(())
            })
        },
    )
    .await?;

    let updated_org = OrganizationStore::find_by_id(DB::Conn(&state.db), &group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let base_url = &state.base_url;
    let scim_group = org_to_scim_group(&state.db, updated_org, base_url).await?;

    Ok(Json(scim_group).into_response())
}

/// Delete Group - DELETE /scim/v2/Groups/:id
pub async fn delete_group(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(group_id): Path<String>,
) -> Result<StatusCode> {
    // A SCIM group is an organization, so deleting one through SCIM would
    // delete a tenant. Always refused; the org is loaded only to authorize.
    let _org = current_scim_org_by_group_id(&state, &scim_auth, &group_id).await?;

    Err(AppError::Forbidden(
        "Group deletion via SCIM is not supported. Please use the Organizations API.".to_string(),
    ))
}
