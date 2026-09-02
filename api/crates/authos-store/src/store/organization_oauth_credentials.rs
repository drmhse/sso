use crate::db::DB;
use crate::entities::organization_oauth_credentials;
use crate::entities::prelude::OrganizationOauthCredentials;
use crate::error::Result;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct OrganizationOAuthCredentialsStore;

impl OrganizationOAuthCredentialsStore {
    /// Find OAuth credentials for an organization and provider
    pub async fn find_by_org_and_provider(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<Option<organization_oauth_credentials::Model>> {
        let result = OrganizationOauthCredentials::find()
            .filter(organization_oauth_credentials::Column::OrgId.eq(org_id))
            .filter(organization_oauth_credentials::Column::Provider.eq(provider))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Upsert OAuth credentials (insert or update)
    pub async fn upsert(
        db: DB<'_>,
        new_record_id: &str,
        org_id: &str,
        provider: &str,
        client_id: &str,
        client_secret_encrypted: Vec<u8>,
        encryption_key_id: &str,
    ) -> Result<organization_oauth_credentials::Model> {
        // Try to find existing credentials
        if let Some(existing) = Self::find_by_org_and_provider(db.clone(), org_id, provider).await?
        {
            if existing.id != new_record_id {
                return Err(crate::error::AppError::InternalServerError(
                    "OAuth credential changed concurrently; retry the request".to_string(),
                ));
            }
            // Update existing
            let mut active_model: organization_oauth_credentials::ActiveModel = existing.into();
            active_model.client_id = Set(client_id.to_string());
            active_model.client_secret_encrypted = Set(client_secret_encrypted);
            active_model.encryption_key_id = Set(encryption_key_id.to_string());
            active_model.updated_at = Set(chrono::Utc::now().naive_utc());

            let updated = active_model.update(&db).await?;
            Ok(updated)
        } else {
            // Insert new
            let now = chrono::Utc::now().naive_utc();
            let new_creds = organization_oauth_credentials::ActiveModel {
                id: Set(new_record_id.to_string()),
                org_id: Set(org_id.to_string()),
                provider: Set(provider.to_string()),
                client_id: Set(client_id.to_string()),
                client_secret_encrypted: Set(client_secret_encrypted),
                encryption_key_id: Set(encryption_key_id.to_string()),
                created_at: Set(now),
                updated_at: Set(now),
            };

            let inserted = new_creds.insert(&db).await?;
            Ok(inserted)
        }
    }

    /// Get only the client_id for an organization and provider
    pub async fn find_client_id(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<Option<String>> {
        use sea_orm::QuerySelect;

        let result = OrganizationOauthCredentials::find()
            .filter(organization_oauth_credentials::Column::OrgId.eq(org_id))
            .filter(organization_oauth_credentials::Column::Provider.eq(provider))
            .select_only()
            .column(organization_oauth_credentials::Column::ClientId)
            .into_tuple::<String>()
            .one(&db)
            .await?;

        Ok(result)
    }
}
