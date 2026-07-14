use crate::entities::prelude::Services;
use crate::entities::services;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, Set,
};
use uuid::Uuid;

pub struct ServiceStore;

impl ServiceStore {
    /// Find a service by ID
    pub async fn find_by_id(db: DB<'_>, service_id: &str) -> Result<Option<services::Model>> {
        let result = Services::find()
            .filter(services::Column::Id.eq(service_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a service by client ID
    pub async fn find_by_client_id(db: DB<'_>, client_id: &str) -> Result<Option<services::Model>> {
        let result = Services::find()
            .filter(services::Column::ClientId.eq(client_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a service by organization and slug
    pub async fn find_by_org_and_slug(
        db: DB<'_>,
        org_id: &str,
        slug: &str,
    ) -> Result<Option<services::Model>> {
        let result = Services::find()
            .filter(services::Column::OrgId.eq(org_id))
            .filter(services::Column::Slug.eq(slug))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a service by slug within an organization (by slug and org_id)
    /// This is an alias for find_by_org_and_slug for better API clarity
    pub async fn find_by_slug_and_org(
        db: DB<'_>,
        slug: &str,
        org_id: &str,
    ) -> Result<Option<services::Model>> {
        Self::find_by_org_and_slug(db, org_id, slug).await
    }

    /// Find a service by organization slug and service slug (with JOIN)
    pub async fn find_by_org_slug_and_service_slug(
        db: DB<'_>,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<Option<services::Model>> {
        use crate::entities::organizations;
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        let result = Services::find()
            .join(JoinType::InnerJoin, services::Relation::Organizations.def())
            .filter(organizations::Column::Slug.eq(org_slug))
            .filter(services::Column::Slug.eq(service_slug))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a service by client ID, organization slug, and service slug (with JOIN)
    /// Used for device flow validation
    pub async fn find_by_client_id_and_slugs(
        db: DB<'_>,
        client_id: &str,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<Option<services::Model>> {
        use crate::entities::organizations;
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        let result = Services::find()
            .join(JoinType::InnerJoin, services::Relation::Organizations.def())
            .filter(services::Column::ClientId.eq(client_id))
            .filter(organizations::Column::Slug.eq(org_slug))
            .filter(services::Column::Slug.eq(service_slug))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new service
    pub async fn create(
        db: DB<'_>,
        org_id: &str,
        slug: &str,
        name: &str,
        service_type: &str,
        client_id: &str,
    ) -> Result<services::Model> {
        let new_service = services::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            slug: Set(slug.to_string()),
            name: Set(name.to_string()),
            service_type: Set(service_type.to_string()),
            client_id: Set(client_id.to_string()),
            ..Default::default()
        };

        let service = new_service.insert(&db).await?;
        Ok(service)
    }

    /// Create a new service with all optional fields
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_options(
        db: DB<'_>,
        service_id: &str,
        org_id: &str,
        slug: &str,
        name: &str,
        service_type: &str,
        client_id: &str,
        client_secret_hash: &str,
        github_scopes: Option<&str>,
        microsoft_scopes: Option<&str>,
        google_scopes: Option<&str>,
        redirect_uris: Option<&str>,
        device_activation_uri: Option<&str>,
        resource_uris: Option<&str>,
    ) -> Result<services::Model> {
        let new_service = services::ActiveModel {
            id: Set(service_id.to_string()),
            org_id: Set(org_id.to_string()),
            slug: Set(slug.to_string()),
            name: Set(name.to_string()),
            service_type: Set(service_type.to_string()),
            client_id: Set(client_id.to_string()),
            client_secret_hash: Set(client_secret_hash.to_string()),
            github_scopes: Set(github_scopes.map(|s| s.to_string())),
            microsoft_scopes: Set(microsoft_scopes.map(|s| s.to_string())),
            google_scopes: Set(google_scopes.map(|s| s.to_string())),
            redirect_uris: Set(redirect_uris.map(|s| s.to_string())),
            device_activation_uri: Set(device_activation_uri.map(|s| s.to_string())),
            resource_uris: Set(resource_uris.map(|s| s.to_string())),
            ..Default::default()
        };

        let service = new_service.insert(&db).await.map_err(|e| {
            // Convert SeaORM constraint violations to 400 Bad Request errors
            crate::error::handle_sea_orm_error(e)
        })?;
        Ok(service)
    }

    /// Update service name
    pub async fn update_name(db: DB<'_>, service_id: &str, name: &str) -> Result<services::Model> {
        let service = Self::find_by_id(db.clone(), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let mut service_active: services::ActiveModel = service.into();
        service_active.name = Set(name.to_string());

        let updated_service = service_active.update(&db).await?;
        Ok(updated_service)
    }

    /// Update service redirect URIs
    pub async fn update_redirect_uris(
        db: DB<'_>,
        service_id: &str,
        redirect_uris: Option<&str>,
    ) -> Result<services::Model> {
        let service = Self::find_by_id(db.clone(), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let mut service_active: services::ActiveModel = service.into();
        service_active.redirect_uris = Set(redirect_uris.map(|s| s.to_string()));

        let updated_service = service_active.update(&db).await?;
        Ok(updated_service)
    }

    /// Update service scopes
    pub async fn update_scopes(
        db: DB<'_>,
        service_id: &str,
        github_scopes: Option<&str>,
        google_scopes: Option<&str>,
        microsoft_scopes: Option<&str>,
    ) -> Result<services::Model> {
        let service = Self::find_by_id(db.clone(), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let mut service_active: services::ActiveModel = service.into();
        service_active.github_scopes = Set(github_scopes.map(|s| s.to_string()));
        service_active.google_scopes = Set(google_scopes.map(|s| s.to_string()));
        service_active.microsoft_scopes = Set(microsoft_scopes.map(|s| s.to_string()));

        let updated_service = service_active.update(&db).await?;
        Ok(updated_service)
    }

    /// Update SAML configuration
    #[allow(clippy::too_many_arguments)]
    pub async fn update_saml_config(
        db: DB<'_>,
        service_id: &str,
        enabled: bool,
        entity_id: Option<&str>,
        acs_url: Option<&str>,
        slo_url: Option<&str>,
        name_id_format: Option<&str>,
        attribute_mapping: Option<&str>,
        sign_assertions: bool,
        sign_response: bool,
    ) -> Result<services::Model> {
        let service = Self::find_by_id(db.clone(), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let mut service_active: services::ActiveModel = service.into();
        service_active.saml_enabled = Set(enabled);
        service_active.saml_entity_id = Set(entity_id.map(|s| s.to_string()));
        service_active.saml_acs_url = Set(acs_url.map(|s| s.to_string()));
        service_active.saml_slo_url = Set(slo_url.map(|s| s.to_string()));
        service_active.saml_name_id_format = Set(name_id_format.map(|s| s.to_string()));
        service_active.saml_attribute_mapping = Set(attribute_mapping.map(|s| s.to_string()));
        service_active.saml_sign_assertions = Set(sign_assertions);
        service_active.saml_sign_response = Set(sign_response);

        let updated_service = service_active.update(&db).await?;
        Ok(updated_service)
    }

    /// Delete a service
    pub async fn delete(db: DB<'_>, service_id: &str) -> Result<()> {
        let service = Self::find_by_id(db.clone(), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let service_active: services::ActiveModel = service.into();
        service_active.delete(&db).await?;

        Ok(())
    }

    /// List all services for an organization
    pub async fn list_by_org(db: DB<'_>, org_id: &str) -> Result<Vec<services::Model>> {
        let services = Services::find()
            .filter(services::Column::OrgId.eq(org_id))
            .all(&db)
            .await?;

        Ok(services)
    }

    /// Count services for an organization
    pub async fn count_by_org(db: DB<'_>, org_id: &str) -> Result<u64> {
        let count = Services::find()
            .filter(services::Column::OrgId.eq(org_id))
            .count(&db)
            .await?;

        Ok(count)
    }

    /// List services with optional filters
    pub async fn list_with_filters(
        db: DB<'_>,
        org_id: &str,
        service_type: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<services::Model>> {
        use sea_orm::QueryOrder;

        let mut query = Services::find()
            .filter(services::Column::OrgId.eq(org_id))
            .order_by_desc(services::Column::CreatedAt);

        if let Some(st) = service_type {
            query = query.filter(services::Column::ServiceType.eq(st));
        }

        if let Some(lim) = limit {
            query = query.limit(lim as u64);
        }

        if let Some(off) = offset {
            query = query.offset(off as u64);
        }

        let services = query.all(&db).await?;
        Ok(services)
    }

    /// Update service with dynamic fields
    #[allow(clippy::too_many_arguments)]
    pub async fn update_dynamic(
        db: DB<'_>,
        org_id: &str,
        slug: &str,
        name: Option<&str>,
        service_type: Option<&str>,
        github_scopes: Option<&str>,
        microsoft_scopes: Option<&str>,
        google_scopes: Option<&str>,
        redirect_uris: Option<&str>,
        device_activation_uri: Option<&str>,
        resource_uris: Option<&str>,
    ) -> Result<services::Model> {
        let service = Self::find_by_org_and_slug(db.clone(), org_id, slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let mut service_active: services::ActiveModel = service.into();

        if let Some(n) = name {
            service_active.name = Set(n.to_string());
        }
        if let Some(st) = service_type {
            service_active.service_type = Set(st.to_string());
        }
        if let Some(gs) = github_scopes {
            service_active.github_scopes = Set(Some(gs.to_string()));
        }
        if let Some(ms) = microsoft_scopes {
            service_active.microsoft_scopes = Set(Some(ms.to_string()));
        }
        if let Some(gos) = google_scopes {
            service_active.google_scopes = Set(Some(gos.to_string()));
        }
        if let Some(ru) = redirect_uris {
            service_active.redirect_uris = Set(Some(ru.to_string()));
        }
        if let Some(dau) = device_activation_uri {
            service_active.device_activation_uri = Set(Some(dau.to_string()));
        }
        if let Some(resources) = resource_uris {
            service_active.resource_uris = Set(Some(resources.to_string()));
        }

        let updated_service = service_active.update(&db).await?;
        Ok(updated_service)
    }

    /// Rotate a service client secret hash.
    pub async fn update_client_secret_hash(
        db: DB<'_>,
        org_id: &str,
        slug: &str,
        client_secret_hash: &str,
    ) -> Result<services::Model> {
        let service = Self::find_by_org_and_slug(db.clone(), org_id, slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let mut service_active: services::ActiveModel = service.into();
        service_active.client_secret_hash = Set(client_secret_hash.to_string());

        let updated_service = service_active.update(&db).await?;
        Ok(updated_service)
    }

    /// Delete service by organization and slug
    pub async fn delete_by_org_and_slug(db: DB<'_>, org_id: &str, slug: &str) -> Result<u64> {
        let result = Services::delete_many()
            .filter(services::Column::OrgId.eq(org_id))
            .filter(services::Column::Slug.eq(slug))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Count all services across the platform
    pub async fn count_all(db: DB<'_>) -> Result<u64> {
        let count = Services::find().count(&db).await?;
        Ok(count)
    }

    /// Check if an origin is allowed based on registered redirect URIs across ALL services.
    ///
    /// This performs a two-step verification for security:
    /// 1. DB: Find rows where redirect_uris string contains the origin (broad filter)
    /// 2. App: Parse JSON and strictly compare URL origins to prevent prefix attacks
    ///
    /// This prevents `https://app.com` from accidentally allowing `https://app.com.attacker.com`.
    pub async fn is_origin_allowed(db: DB<'_>, origin: &str) -> Result<bool> {
        use url::Url;

        // Quick check for invalid origins
        if origin.is_empty() || origin == "null" {
            return Ok(false);
        }

        // 1. Broad SQL filter: Find services that *might* contain this origin
        // We use a LIKE query to reduce the working set.
        // Note: This matches substring, so "https://app.com" matches "https://app.com.evil.com"
        // We MUST validate strictly in step 2.
        let candidates = Services::find()
            .filter(services::Column::RedirectUris.contains(origin))
            .all(&db)
            .await?;

        // 2. Strict validation in memory
        for service in candidates {
            if let Some(json_str) = service.redirect_uris {
                if let Ok(uris) = serde_json::from_str::<Vec<String>>(&json_str) {
                    for uri in uris {
                        // Parse the redirect URI to extract its origin (scheme + host + port)
                        if let Ok(parsed_uri) = Url::parse(&uri) {
                            // Construct the origin string from the redirect URI
                            let uri_origin = parsed_uri.origin().ascii_serialization();

                            // Compare strict equality
                            // Trim trailing slashes for consistent comparison
                            if uri_origin.trim_end_matches('/') == origin.trim_end_matches('/') {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}
