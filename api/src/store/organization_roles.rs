use crate::entities::organization_roles;
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};

pub struct OrganizationRoleStore;

impl OrganizationRoleStore {
    /// Create a new organization role
    pub async fn create(
        db: DB<'_>,
        id: &str,
        org_id: &str,
        slug: &str,
        name: &str,
        description: Option<String>,
        permissions: serde_json::Value,
    ) -> Result<organization_roles::Model> {
        let now = Utc::now().naive_utc();
        let role = organization_roles::ActiveModel {
            id: Set(id.to_string()),
            org_id: Set(org_id.to_string()),
            slug: Set(slug.to_string()),
            name: Set(name.to_string()),
            description: Set(description),
            permissions: Set(permissions),
            created_at: Set(now),
            updated_at: Set(now),
        };

        role.insert(&db).await.map_err(AppError::from)
    }

    /// Update an existing organization role
    pub async fn update(
        db: DB<'_>,
        id: &str,
        name: Option<String>,
        description: Option<Option<String>>,
        permissions: Option<serde_json::Value>,
    ) -> Result<organization_roles::Model> {
        let now = Utc::now().naive_utc();

        let role = organization_roles::Entity::find_by_id(id)
            .one(&db)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

        let mut role: organization_roles::ActiveModel = role.into();

        if let Some(name) = name {
            role.name = Set(name);
        }

        if let Some(description) = description {
            role.description = Set(description);
        }

        if let Some(permissions) = permissions {
            role.permissions = Set(permissions);
        }

        role.updated_at = Set(now);

        role.update(&db).await.map_err(AppError::from)
    }

    /// Find a role by ID
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<organization_roles::Model>> {
        organization_roles::Entity::find_by_id(id)
            .one(&db)
            .await
            .map_err(AppError::from)
    }

    /// Find all roles for an organization
    pub async fn find_by_org(db: DB<'_>, org_id: &str) -> Result<Vec<organization_roles::Model>> {
        organization_roles::Entity::find()
            .filter(organization_roles::Column::OrgId.eq(org_id))
            .order_by_asc(organization_roles::Column::Name)
            .all(&db)
            .await
            .map_err(AppError::from)
    }

    /// Find a role by organization and slug
    pub async fn find_by_org_and_slug(
        db: DB<'_>,
        org_id: &str,
        slug: &str,
    ) -> Result<Option<organization_roles::Model>> {
        organization_roles::Entity::find()
            .filter(organization_roles::Column::OrgId.eq(org_id))
            .filter(organization_roles::Column::Slug.eq(slug))
            .one(&db)
            .await
            .map_err(AppError::from)
    }

    /// Delete a role (and cascade due to DB constraints if any, though usually cascade on FK)
    pub async fn delete(db: DB<'_>, id: &str) -> Result<()> {
        organization_roles::Entity::delete_by_id(id)
            .exec(&db)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }
}
