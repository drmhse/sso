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
    pub async fn upsert(
        db: DB<'_>,
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
                id: Set(Uuid::new_v4().to_string()),
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
    pub async fn delete(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<u64> {
        let result = OrganizationBillingCredentials::delete_many()
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Disable billing credentials (soft delete)
    pub async fn disable(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<u64> {
        // Find and update all matching credentials
        let credentials = OrganizationBillingCredentials::find()
            .filter(organization_billing_credentials::Column::OrgId.eq(org_id))
            .filter(organization_billing_credentials::Column::Provider.eq(provider))
            .all(&db)
            .await?;

        let mut count = 0u64;
        for cred in credentials {
            let mut active_model: organization_billing_credentials::ActiveModel = cred.into();
            active_model.enabled = Set(false);
            active_model.updated_at = Set(chrono::Utc::now().naive_utc());
            active_model.update(&db).await?;
            count += 1;
        }

        Ok(count)
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
