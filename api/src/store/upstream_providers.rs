use crate::entities::prelude::UpstreamProviders;
use crate::entities::{upstream_providers, verified_domains};
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait,
    Set,
};

pub struct UpstreamProviderStore;

impl UpstreamProviderStore {
    pub const METADATA_ALLOW_DOMAIN_BINDINGS: &str = "allow_domain_bindings";

    /// Find an upstream provider by ID
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<upstream_providers::Model>> {
        let result = UpstreamProviders::find_by_id(id)
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(result)
    }

    /// Find an upstream provider by organization and connection ID
    pub async fn find_by_connection_id(
        db: DB<'_>,
        org_id: &str,
        connection_id: &str,
    ) -> Result<Option<upstream_providers::Model>> {
        let result = UpstreamProviders::find()
            .filter(upstream_providers::Column::OrgId.eq(org_id))
            .filter(upstream_providers::Column::ConnectionId.eq(connection_id))
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(result)
    }

    /// Resolve a provider that is bound to an organization's verified domain route.
    /// This supports explicitly shared upstream providers reused by many tenant orgs.
    pub async fn find_domain_routed_by_connection_id(
        db: DB<'_>,
        org_id: &str,
        connection_id: &str,
    ) -> Result<Option<upstream_providers::Model>> {
        let result = UpstreamProviders::find()
            .join_rev(
                JoinType::InnerJoin,
                verified_domains::Relation::UpstreamProviders.def(),
            )
            .filter(verified_domains::Column::OrgId.eq(org_id))
            .filter(verified_domains::Column::Verified.eq(true))
            .filter(upstream_providers::Column::ConnectionId.eq(connection_id))
            .filter(upstream_providers::Column::Enabled.eq(true))
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(result.filter(Self::allows_domain_bindings))
    }

    pub fn allows_domain_bindings(provider: &upstream_providers::Model) -> bool {
        provider
            .metadata
            .as_deref()
            .and_then(|metadata| serde_json::from_str::<serde_json::Value>(metadata).ok())
            .and_then(|metadata| {
                metadata
                    .get(Self::METADATA_ALLOW_DOMAIN_BINDINGS)
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false)
    }

    /// Find all upstream providers for an organization
    pub async fn find_by_org(db: DB<'_>, org_id: &str) -> Result<Vec<upstream_providers::Model>> {
        let results = UpstreamProviders::find()
            .filter(upstream_providers::Column::OrgId.eq(org_id))
            .all(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(results)
    }

    /// Create a new upstream provider
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        id: &str,
        org_id: &str,
        connection_id: &str,
        name: &str,
        provider_type: &str,
        client_id: &str,
        client_secret_encrypted: Vec<u8>,
        encryption_key_id: &str,
        authorization_url: Option<&str>,
        token_url: Option<&str>,
        userinfo_url: Option<&str>,
        discovery_url: Option<&str>,
        scopes: Option<&str>,
        issuer: Option<&str>,
        metadata: Option<&str>,
    ) -> Result<upstream_providers::Model> {
        let now = chrono::Utc::now().naive_utc();

        let provider = upstream_providers::ActiveModel {
            id: Set(id.to_string()),
            org_id: Set(org_id.to_string()),
            connection_id: Set(connection_id.to_string()),
            name: Set(name.to_string()),
            provider_type: Set(provider_type.to_string()),
            client_id: Set(client_id.to_string()),
            client_secret_encrypted: Set(client_secret_encrypted),
            encryption_key_id: Set(encryption_key_id.to_string()),
            authorization_url: Set(authorization_url.map(|s| s.to_string())),
            token_url: Set(token_url.map(|s| s.to_string())),
            userinfo_url: Set(userinfo_url.map(|s| s.to_string())),
            discovery_url: Set(discovery_url.map(|s| s.to_string())),
            scopes: Set(scopes.map(|s| s.to_string())),
            issuer: Set(issuer.map(|s| s.to_string())),
            metadata: Set(metadata.map(|s| s.to_string())),
            enabled: Set(true),
            created_at: Set(now.clone()),
            updated_at: Set(now),
        };

        let result = provider.insert(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to create provider: {}", e))
        })?;

        Ok(result)
    }

    /// Update an upstream provider
    pub async fn update(
        db: DB<'_>,
        provider_id: &str,
        name: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<upstream_providers::Model> {
        let now = chrono::Utc::now().naive_utc();

        let provider = UpstreamProviders::find_by_id(provider_id)
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Provider not found".to_string()))?;

        let mut provider: upstream_providers::ActiveModel = provider.into();

        if let Some(name) = name {
            provider.name = Set(name.to_string());
        }

        if let Some(enabled) = enabled {
            provider.enabled = Set(enabled);
        }

        provider.updated_at = Set(now);

        let result = provider.update(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to update provider: {}", e))
        })?;

        Ok(result)
    }

    /// Delete an upstream provider
    pub async fn delete(db: DB<'_>, provider_id: &str) -> Result<()> {
        let provider = UpstreamProviders::find_by_id(provider_id)
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Provider not found".to_string()))?;

        let provider: upstream_providers::ActiveModel = provider.into();
        provider.delete(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to delete provider: {}", e))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
        verified_domains::VerifiedDomainStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use uuid::Uuid;

    #[tokio::test]
    async fn domain_route_can_resolve_explicitly_shared_provider_from_another_org() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let provider_owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "provider-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create provider owner")
        .0;
        let tenant_owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "tenant-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create tenant owner")
        .0;
        let (provider_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "identity-hub",
            "Identity Hub",
            &provider_owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create provider org");
        let (tenant_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &tenant_owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create tenant org");
        let provider = UpstreamProviderStore::create(
            DB::Conn(&db),
            &Uuid::new_v4().to_string(),
            &provider_org.id,
            "okta-main",
            "Okta Main",
            "oidc",
            "client",
            Vec::new(),
            "test-key",
            Some("https://idp.example.com/authorize"),
            Some("https://idp.example.com/token"),
            Some("https://idp.example.com/userinfo"),
            None,
            Some("openid email profile"),
            Some("https://idp.example.com"),
            Some(r#"{"allow_domain_bindings":true}"#),
        )
        .await
        .expect("create shared provider");
        let domain = VerifiedDomainStore::create(
            DB::Conn(&db),
            &Uuid::new_v4().to_string(),
            &tenant_org.id,
            "acme.com",
            "verify-token",
            Some(&provider.id),
            None,
        )
        .await
        .expect("create domain route");
        VerifiedDomainStore::mark_verified(DB::Conn(&db), &domain.id)
            .await
            .expect("verify domain");

        assert!(UpstreamProviderStore::find_by_connection_id(
            DB::Conn(&db),
            &tenant_org.id,
            "okta-main"
        )
        .await
        .expect("lookup same-org provider")
        .is_none());

        let resolved = UpstreamProviderStore::find_domain_routed_by_connection_id(
            DB::Conn(&db),
            &tenant_org.id,
            "okta-main",
        )
        .await
        .expect("resolve domain-routed provider")
        .expect("shared provider should resolve");

        assert_eq!(resolved.id, provider.id);
    }
}
