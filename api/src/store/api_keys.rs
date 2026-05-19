use crate::entities::api_keys;
use crate::entities::prelude::ApiKeys;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};
use uuid::Uuid;

pub struct ApiKeyStore;

impl ApiKeyStore {
    /// Find an API key by ID
    pub async fn find_by_id(db: DB<'_>, api_key_id: &str) -> Result<Option<api_keys::Model>> {
        let result = ApiKeys::find()
            .filter(api_keys::Column::Id.eq(api_key_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find an API key by ID and service_id (for security validation)
    pub async fn find_by_id_and_service(
        db: DB<'_>,
        api_key_id: &str,
        service_id: &str,
    ) -> Result<Option<api_keys::Model>> {
        let result = ApiKeys::find()
            .filter(api_keys::Column::Id.eq(api_key_id))
            .filter(api_keys::Column::ServiceId.eq(service_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find an API key by prefix
    pub async fn find_by_prefix(db: DB<'_>, prefix: &str) -> Result<Option<api_keys::Model>> {
        let result = ApiKeys::find()
            .filter(api_keys::Column::Prefix.eq(prefix))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new API key
    pub async fn create(
        db: DB<'_>,
        service_id: &str,
        name: &str,
        prefix: &str,
        key_hash: &str,
        permissions: &str,
        created_by: &str,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<api_keys::Model> {
        let new_api_key = api_keys::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            service_id: Set(service_id.to_string()),
            name: Set(name.to_string()),
            prefix: Set(prefix.to_string()),
            key_hash: Set(key_hash.to_string()),
            permissions: Set(permissions.to_string()),
            created_by: Set(created_by.to_string()),
            expires_at: Set(expires_at),
            ..Default::default()
        };

        let api_key = new_api_key.insert(&db).await?;
        Ok(api_key)
    }

    /// Update last_used_at timestamp
    ///
    /// OPTIMIZATION: Only writes to DB if >5 minutes since last update.
    /// This dramatically reduces write pressure for frequently-used API keys.
    pub async fn update_last_used(db: DB<'_>, api_key_id: &str) -> Result<api_keys::Model> {
        let api_key = Self::find_by_id(db.clone(), api_key_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

        // OPTIMIZATION: Only update if >5 minutes since last update
        if let Some(last_used) = api_key.last_used_at {
            let now = chrono::Utc::now().naive_utc();
            let minutes_since_update = (now - last_used).num_minutes();
            if minutes_since_update <= 5 {
                // Skip redundant write - key was recently used
                return Ok(api_key);
            }
        }

        let mut key_active: api_keys::ActiveModel = api_key.into();
        key_active.last_used_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_key = key_active.update(&db).await?;
        Ok(updated_key)
    }

    /// Delete an API key
    pub async fn delete(db: DB<'_>, api_key_id: &str) -> Result<()> {
        let api_key = Self::find_by_id(db.clone(), api_key_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

        let key_active: api_keys::ActiveModel = api_key.into();
        key_active.delete(&db).await?;

        Ok(())
    }

    /// List all API keys for a service with pagination
    pub async fn list_by_service(
        db: DB<'_>,
        service_id: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<api_keys::Model>> {
        use sea_orm::QueryOrder;

        let api_keys = ApiKeys::find()
            .filter(api_keys::Column::ServiceId.eq(service_id))
            .order_by_desc(api_keys::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .all(&db)
            .await?;

        Ok(api_keys)
    }

    /// Count API keys for a service
    pub async fn count_by_service(db: DB<'_>, service_id: &str) -> Result<u64> {
        use sea_orm::PaginatorTrait;

        let count = ApiKeys::find()
            .filter(api_keys::Column::ServiceId.eq(service_id))
            .count(&db)
            .await?;

        Ok(count)
    }

    /// Delete expired API keys
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = chrono::Utc::now().naive_utc();

        let result = ApiKeys::delete_many()
            .filter(api_keys::Column::ExpiresAt.is_not_null())
            .filter(api_keys::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}
