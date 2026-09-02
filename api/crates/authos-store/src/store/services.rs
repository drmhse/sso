use crate::db::DB;
use crate::entities::prelude::Services;
use crate::entities::services;
use crate::error::{AppError, Result};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
use std::collections::HashMap;
use uuid::Uuid;

pub struct ServiceStore;

#[derive(Debug, FromQueryResult)]
struct CountByOrg {
    org_id: String,
    count: i64,
}

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

    /// Find services by slug within an organization.
    pub async fn find_by_org_and_slugs(
        db: DB<'_>,
        org_id: &str,
        slugs: &[String],
    ) -> Result<Vec<services::Model>> {
        if slugs.is_empty() {
            return Ok(Vec::new());
        }

        let result = Services::find()
            .filter(services::Column::OrgId.eq(org_id))
            .filter(services::Column::Slug.is_in(slugs.iter().cloned()))
            .all(&db)
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

    /// Count services grouped by organization ID.
    pub async fn count_by_orgs(db: DB<'_>, org_ids: &[String]) -> Result<HashMap<String, i64>> {
        if org_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = Services::find()
            .filter(services::Column::OrgId.is_in(org_ids.iter().cloned()))
            .select_only()
            .column(services::Column::OrgId)
            .column_as(services::Column::Id.count(), "count")
            .group_by(services::Column::OrgId)
            .into_model::<CountByOrg>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.org_id, row.count))
            .collect())
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
            github_scopes: Set(github_scopes.map(std::string::ToString::to_string)),
            microsoft_scopes: Set(microsoft_scopes.map(std::string::ToString::to_string)),
            google_scopes: Set(google_scopes.map(std::string::ToString::to_string)),
            redirect_uris: Set(redirect_uris.map(std::string::ToString::to_string)),
            device_activation_uri: Set(device_activation_uri.map(std::string::ToString::to_string)),
            resource_uris: Set(resource_uris.map(std::string::ToString::to_string)),
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
        service_active.redirect_uris = Set(redirect_uris.map(std::string::ToString::to_string));

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
        service_active.github_scopes = Set(github_scopes.map(std::string::ToString::to_string));
        service_active.google_scopes = Set(google_scopes.map(std::string::ToString::to_string));
        service_active.microsoft_scopes =
            Set(microsoft_scopes.map(std::string::ToString::to_string));

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
        service_active.saml_entity_id = Set(entity_id.map(std::string::ToString::to_string));
        service_active.saml_acs_url = Set(acs_url.map(std::string::ToString::to_string));
        service_active.saml_slo_url = Set(slo_url.map(std::string::ToString::to_string));
        service_active.saml_name_id_format =
            Set(name_id_format.map(std::string::ToString::to_string));
        service_active.saml_attribute_mapping =
            Set(attribute_mapping.map(std::string::ToString::to_string));
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
            query = query.limit(crate::utils::pagination::store_u64(lim, 0, 1000).0);
        }

        if let Some(off) = offset {
            query = query.offset(crate::utils::pagination::store_u64(1, off, 1000).1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::organizations::OrganizationStore;
    use crate::store::users::{UserCreationOptions, UserStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    async fn create_test_service(db: &sea_orm::DatabaseConnection, id: &str, org_id: &str) {
        ServiceStore::create_with_options(
            DB::Conn(db),
            id,
            org_id,
            id,
            id,
            "web",
            &format!("client-{}", id),
            "secret-hash",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create service");
    }

    #[tokio::test]
    async fn count_by_orgs_groups_services_in_one_query_shape() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let (owner, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner");

        let org_1 = OrganizationStore::create(DB::Conn(&db), "org-1", "Org 1", &owner.id, None)
            .await
            .expect("create org 1");
        let org_2 = OrganizationStore::create(DB::Conn(&db), "org-2", "Org 2", &owner.id, None)
            .await
            .expect("create org 2");
        let org_3 = OrganizationStore::create(DB::Conn(&db), "org-3", "Org 3", &owner.id, None)
            .await
            .expect("create org 3");

        create_test_service(&db, "svc-1", &org_1.id).await;
        create_test_service(&db, "svc-2", &org_1.id).await;
        create_test_service(&db, "svc-3", &org_2.id).await;

        let counts = ServiceStore::count_by_orgs(
            DB::Conn(&db),
            &[org_1.id.clone(), org_2.id.clone(), org_3.id.clone()],
        )
        .await
        .expect("count by orgs");

        assert_eq!(counts.get(&org_1.id), Some(&2));
        assert_eq!(counts.get(&org_2.id), Some(&1));
        assert!(!counts.contains_key(&org_3.id));
    }
}

#[cfg(test)]
mod store_service_tests {
    use super::*;
    use crate::store::organizations::OrganizationStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, DatabaseConnection};
    use uuid::Uuid;

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    async fn make_service(db: &DatabaseConnection, slug: &str) -> services::Model {
        let service_id = Uuid::new_v4().to_string();
        let owner = crate::store::users::UserStore::create(
            DB::Conn(db),
            &format!("{slug}-o@example.test"),
            None,
            false,
        )
        .await
        .expect("create owner");
        let (org, _) =
            OrganizationStore::create_with_owner(DB::Conn(db), slug, slug, &owner.id, None)
                .await
                .expect("create org");
        ServiceStore::create_with_options(
            DB::Conn(db),
            &service_id,
            &org.id,
            slug,
            slug,
            "web",
            &Uuid::new_v4().to_string(),
            "hash",
            None,
            None,
            None,
            Some(r#"["https://app.example.test/cb"]"#),
            None,
            None,
        )
        .await
        .expect("create service")
    }

    #[tokio::test]
    async fn origin_allowlisting_accepts_registered_and_refuses_unknowns() {
        let db = db().await;
        make_service(&db, "origin-portal").await;

        // Origins are compared scheme+host only; paths are irrelevant.
        assert!(
            ServiceStore::is_origin_allowed(DB::Conn(&db), "https://app.example.test")
                .await
                .unwrap(),
            "a registered redirect origin must be allowed"
        );
        assert!(
            !ServiceStore::is_origin_allowed(DB::Conn(&db), "https://evil.example.test")
                .await
                .unwrap(),
            "an unregistered origin must be refused"
        );
    }

    #[tokio::test]
    async fn lookups_slugs_counts_and_updates_round_trip() {
        let db = db().await;
        let service = make_service(&db, "lookup-portal").await;

        // Multi-slug lookup.
        let found = ServiceStore::find_by_org_and_slugs(
            DB::Conn(&db),
            &service.org_id,
            &["missing".to_string(), service.slug.clone()],
        )
        .await
        .expect("find by slugs");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].slug, service.slug);

        // Slug-pair lookup.
        let by_pair = ServiceStore::find_by_org_slug_and_service_slug(
            DB::Conn(&db),
            "lookup-portal",
            &service.slug,
        )
        .await
        .expect("find by slug pair")
        .expect("service found via org+slug");
        assert_eq!(by_pair.id, service.id);

        // Redirect URI update.
        let updated = ServiceStore::update_redirect_uris(
            DB::Conn(&db),
            &service.id,
            Some(r#"["https://new.example.test/cb"]"#),
        )
        .await
        .expect("update redirect uris");
        assert!(updated.redirect_uris.unwrap().contains("new.example.test"));

        assert!(ServiceStore::count_all(DB::Conn(&db)).await.unwrap() >= 1);

        ServiceStore::delete(DB::Conn(&db), &service.id)
            .await
            .expect("delete service");
        match ServiceStore::find_by_id(DB::Conn(&db), &service.id)
            .await
            .unwrap()
        {
            None => {}
            Some(_) => panic!("deleted service still present"),
        }
    }
}
