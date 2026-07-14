//! Store for organization billing credentials (BYOP - Bring Your Own Payment)

use crate::entities::organization_billing_credentials;
use crate::entities::prelude::OrganizationBillingCredentials;
use crate::error::Result;
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct OrganizationBillingCredentialsStore;

impl OrganizationBillingCredentialsStore {
    /// Find billing credentials for an organization and provider
    pub async fn find_by_org_and_provider(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<Option<organization_billing_credentials::Model>> {
        let result = OrganizationBillingCredentials::find()
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .filter(organization_billing_credentials::Column::Enabled.eq(true))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find billing credentials for an organization and provider with mode
    pub async fn find_by_org_provider_mode(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
        mode: &str,
    ) -> Result<Option<organization_billing_credentials::Model>> {
        let result = OrganizationBillingCredentials::find()
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .filter(organization_billing_credentials::Column::Mode.eq(mode))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Upsert billing credentials (insert or update)
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        db: DB<'_>,
        new_record_id: Option<&str>,
        org_id: &str,
        provider: &str,
        mode: &str,
        api_key_encrypted: Vec<u8>,
        webhook_secret_encrypted: Vec<u8>,
        encryption_key_id: &str,
    ) -> Result<organization_billing_credentials::Model> {
        // Try to find existing credentials for this org/provider/mode
        if let Some(existing) =
            Self::find_by_org_provider_mode(db.clone(), org_id, provider, mode).await?
        {
            if new_record_id.is_some_and(|expected| expected != existing.id) {
                return Err(crate::error::AppError::InternalServerError(
                    "Billing credential changed concurrently; retry the request".to_string(),
                ));
            }
            // Update existing
            let mut active_model: organization_billing_credentials::ActiveModel = existing.into();
            active_model.api_key_encrypted = Set(api_key_encrypted);
            active_model.webhook_secret_encrypted = Set(webhook_secret_encrypted);
            active_model.encryption_key_id = Set(encryption_key_id.to_string());
            active_model.enabled = Set(true);
            active_model.updated_at = Set(chrono::Utc::now().naive_utc());

            let updated = active_model.update(&db).await?;
            Ok(updated)
        } else {
            // Insert new
            let now = chrono::Utc::now().naive_utc();
            let new_creds = organization_billing_credentials::ActiveModel {
                id: Set(new_record_id
                    .map(str::to_string)
                    .unwrap_or_else(|| Uuid::new_v4().to_string())),
                org_id: Set(org_id.to_string()),
                provider: Set(provider.to_string()),
                mode: Set(mode.to_string()),
                api_key_encrypted: Set(api_key_encrypted),
                webhook_secret_encrypted: Set(webhook_secret_encrypted),
                encryption_key_id: Set(encryption_key_id.to_string()),
                enabled: Set(true),
                created_at: Set(now),
                updated_at: Set(now),
            };

            let inserted = new_creds.insert(&db).await?;
            Ok(inserted)
        }
    }

    /// Get credential status (without returning encrypted data)
    pub async fn get_status(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<Option<BillingCredentialStatus>> {
        let result = OrganizationBillingCredentials::find()
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .one(&db)
            .await?;

        Ok(result.map(|creds| BillingCredentialStatus {
            configured: true,
            provider: creds.provider,
            mode: creds.mode,
            enabled: creds.enabled,
        }))
    }

    /// Delete billing credentials for an organization and provider
    pub async fn delete(db: DB<'_>, org_id: &str, provider: &str) -> Result<u64> {
        let result = OrganizationBillingCredentials::delete_many()
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Disable billing credentials (soft delete)
    pub async fn disable(db: DB<'_>, org_id: &str, provider: &str) -> Result<u64> {
        let result = OrganizationBillingCredentials::update_many()
            .set(organization_billing_credentials::ActiveModel {
                enabled: Set(false),
                updated_at: Set(chrono::Utc::now().naive_utc()),
                ..Default::default()
            })
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}

/// Status of billing credentials (safe to return to clients)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BillingCredentialStatus {
    pub configured: bool,
    pub provider: String,
    pub mode: String,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::organizations::OrganizationStore;
    use crate::store::users::{UserCreationOptions, UserStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn disable_updates_matching_provider_credentials_in_one_statement() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "billing-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org =
            OrganizationStore::create(DB::Conn(&db), "billing-org", "Billing Org", &owner.id, None)
                .await
                .expect("create org");

        OrganizationBillingCredentialsStore::upsert(
            DB::Conn(&db),
            None,
            &org.id,
            "stripe",
            "test",
            vec![1],
            vec![2],
            "key-1",
        )
        .await
        .expect("insert test stripe credentials");
        OrganizationBillingCredentialsStore::upsert(
            DB::Conn(&db),
            None,
            &org.id,
            "stripe",
            "live",
            vec![3],
            vec![4],
            "key-1",
        )
        .await
        .expect("insert live stripe credentials");
        OrganizationBillingCredentialsStore::upsert(
            DB::Conn(&db),
            None,
            &org.id,
            "paddle",
            "live",
            vec![5],
            vec![6],
            "key-1",
        )
        .await
        .expect("insert paddle credentials");

        let disabled =
            OrganizationBillingCredentialsStore::disable(DB::Conn(&db), &org.id, "stripe")
                .await
                .expect("disable stripe credentials");
        assert_eq!(disabled, 2);

        let credentials = OrganizationBillingCredentials::find()
            .filter(organization_billing_credentials::Column::OrgId.eq(&org.id))
            .all(&db)
            .await
            .expect("load credentials");
        let stripe_enabled = credentials
            .iter()
            .filter(|credential| credential.provider == "stripe")
            .filter(|credential| credential.enabled)
            .count();
        let paddle_enabled = credentials
            .iter()
            .filter(|credential| credential.provider == "paddle")
            .filter(|credential| credential.enabled)
            .count();

        assert_eq!(stripe_enabled, 0);
        assert_eq!(paddle_enabled, 1);
    }

    #[tokio::test]
    async fn billing_credential_mutations_are_org_scoped_and_preserve_other_tenant() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "billing-isolation-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "billing-isolation-a",
            "Billing Isolation A",
            &owner.id,
            None,
        )
        .await
        .expect("create org A");
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "billing-isolation-b",
            "Billing Isolation B",
            &owner.id,
            None,
        )
        .await
        .expect("create org B");
        let target = OrganizationBillingCredentialsStore::upsert(
            DB::Conn(&db),
            None,
            &org_b.id,
            "stripe",
            "live",
            vec![9, 8, 7],
            vec![6, 5, 4],
            "key-b",
        )
        .await
        .expect("insert org B credentials");

        assert_eq!(
            OrganizationBillingCredentialsStore::disable(DB::Conn(&db), &org_a.id, "stripe")
                .await
                .expect("cross-tenant disable is a no-op"),
            0
        );
        assert_eq!(
            OrganizationBillingCredentialsStore::delete(DB::Conn(&db), &org_a.id, "stripe")
                .await
                .expect("cross-tenant delete is a no-op"),
            0
        );

        let unchanged = OrganizationBillingCredentials::find_by_id(&target.id)
            .one(&db)
            .await
            .expect("reload target credentials")
            .expect("other tenant credentials must remain");
        assert_eq!(unchanged.org_id, org_b.id);
        assert!(unchanged.enabled);
        assert_eq!(unchanged.api_key_encrypted, vec![9, 8, 7]);
        assert_eq!(unchanged.webhook_secret_encrypted, vec![6, 5, 4]);
        assert_eq!(unchanged.encryption_key_id, "key-b");
    }
}
