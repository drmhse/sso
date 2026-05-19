use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_ORG_ROLES_MANAGE};
use crate::state::AppState;
use crate::store::{
    organization_roles::OrganizationRoleStore, organizations::OrganizationStore, DB,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

impl From<crate::entities::organization_roles::Model> for RoleResponse {
    fn from(model: crate::entities::organization_roles::Model) -> Self {
        let permissions = model
            .permissions
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            id: model.id,
            org_id: model.org_id,
            slug: model.slug,
            name: model.name,
            description: model.description,
            permissions,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
}

/// GET /api/organizations/:org_slug/roles
/// List all custom roles for an organization
pub async fn list_roles(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<Vec<RoleResponse>>> {
    // 1. Resolve Org
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // 2. Check Permission
    // Even 'members' might want to see roles (to know what roles exist), but managing them requires permission.
    // For listing, we can allow anyone who can manage roles OR just verify basic membership.
    // Let's rely on CAP_ORG_ROLES_MANAGE for now to be safe, or just membership if we want transparency.
    // Given the UI shows roles in settings, typically admins see this.
    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        // Fallback: If they are just listing, maybe we allow it?
        // But for "Roles Editor", it's an admin feature.
        return Err(AppError::Forbidden(
            "Insufficient permissions to view roles".to_string(),
        ));
    }

    // 3. Fetch Custom Roles
    let custom_roles = OrganizationRoleStore::find_by_org(DB::Conn(&state.db), &org.id).await?;

    // 4. Combine with Default Roles
    let mut all_roles = Vec::new();

    // Add default roles
    let now = chrono::Utc::now().naive_utc();

    all_roles.push(RoleResponse {
        id: "role_owner".to_string(),
        org_id: org.id.clone(),
        slug: "owner".to_string(),
        name: "Owner".to_string(),
        description: Some("Full access to all resources and settings".to_string()),
        permissions: vec!["*".to_string()], // improved permission representation
        created_at: now,
        updated_at: now,
    });

    all_roles.push(RoleResponse {
        id: "role_admin".to_string(),
        org_id: org.id.clone(),
        slug: "admin".to_string(),
        name: "Admin".to_string(),
        description: Some("Manage members, services, and billing".to_string()),
        permissions: vec!["org:manage".to_string()],
        created_at: now,
        updated_at: now,
    });

    all_roles.push(RoleResponse {
        id: "role_member".to_string(),
        org_id: org.id.clone(),
        slug: "member".to_string(),
        name: "Member".to_string(),
        description: Some("View access to assigned services".to_string()),
        permissions: vec!["org:view".to_string()],
        created_at: now,
        updated_at: now,
    });

    // Append custom roles
    for role in custom_roles {
        all_roles.push(RoleResponse::from(role));
    }

    Ok(Json(all_roles))
}

/// POST /api/organizations/:org_slug/roles
/// Create a new custom role
pub async fn create_role(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to create roles".to_string(),
        ));
    }

    // Validate slug uniqueness
    if OrganizationRoleStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &req.slug)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest(
            "Role with this slug already exists".to_string(),
        ));
    }

    // Determine permissions JSON
    let permissions_json = serde_json::to_value(req.permissions).unwrap();

    let role = OrganizationRoleStore::create(
        DB::Conn(&state.db),
        &Uuid::new_v4().to_string(),
        &org.id,
        &req.slug,
        &req.name,
        req.description,
        permissions_json,
    )
    .await?;

    Ok(Json(RoleResponse::from(role)))
}

/// GET /api/organizations/:org_slug/roles/:role_id
/// Get details of a specific role
pub async fn get_role(
    State(state): State<AppState>,
    Path((org_slug, role_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<RoleResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Allow viewing if you can manage roles
    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view role details".to_string(),
        ));
    }

    let role = OrganizationRoleStore::find_by_id(DB::Conn(&state.db), &role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

    if role.org_id != org.id {
        return Err(AppError::NotFound(
            "Role not found in this organization".to_string(),
        ));
    }

    Ok(Json(RoleResponse::from(role)))
}

/// PUT /api/organizations/:org_slug/roles/:role_id
/// Update a role
pub async fn update_role(
    State(state): State<AppState>,
    Path((org_slug, role_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to update roles".to_string(),
        ));
    }

    let role = OrganizationRoleStore::find_by_id(DB::Conn(&state.db), &role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

    if role.org_id != org.id {
        return Err(AppError::NotFound(
            "Role not found in this organization".to_string(),
        ));
    }

    let permissions_json = req.permissions.map(|p| serde_json::to_value(p).unwrap());

    // Wrap description in Option<Option<String>> accurately
    // The store expects Option<Option<String>> for nullable update
    // UpdateRoleRequest has description: Option<String>.
    // If field is missing (None), we don't update.
    // If field is present (Some(val)), we update.
    // BUT we need to support setting to NULL?
    // For simplicity, let's assume if they send Some(string), we set it.
    // If they want to clear it, they might send empty string or we need a specific nullable DTO.
    // Given the simplified struct, let's treat Some(desc) as "set to desc".
    // Wait, the Store update signature: `description: Option<Option<String>>`
    // usage: None -> no change. Some(None) -> set to null. Some(Some("foo")) -> set to "foo".
    // Our request DTO has `description: Option<String>`.
    // It cannot distinguish "missing" from "null" unless we use a specific deserializer or skip_serializing_if logic.
    // For now, let's map `Some(d)` to `Some(Some(d))` and ignore clearing. (MVP limitation).
    // Or better, assume we don't clear descriptions often.

    let description_update = req.description.map(Some);

    let updated_role = OrganizationRoleStore::update(
        DB::Conn(&state.db),
        &role_id,
        req.name,
        description_update,
        permissions_json,
    )
    .await?;

    Ok(Json(RoleResponse::from(updated_role)))
}

/// DELETE /api/organizations/:org_slug/roles/:role_id
/// Delete a role
pub async fn delete_role(
    State(state): State<AppState>,
    Path((org_slug, role_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to delete roles".to_string(),
        ));
    }

    let role = OrganizationRoleStore::find_by_id(DB::Conn(&state.db), &role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

    if role.org_id != org.id {
        return Err(AppError::NotFound(
            "Role not found in this organization".to_string(),
        ));
    }

    OrganizationRoleStore::delete(DB::Conn(&state.db), &role_id).await?;

    Ok(StatusCode::NO_CONTENT)
}
