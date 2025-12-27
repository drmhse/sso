//! SIEM Configuration Store
//!
//! Manages SIEM integration configurations for organizations.
//! Supports Datadog, Splunk, Elastic, and custom SIEM providers.

use crate::entities::siem_configs;
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

pub struct SiemConfigStore;

impl SiemConfigStore {
    /// Create a new SIEM configuration
    pub async fn create(
        db: DB<'_>,
        org_id: &str,
        name: &str,
        provider_type: &str,
        endpoint_url: &str,
        api_key: Option<String>,
        auth_header: Option<String>,
        batch_size: Option<i32>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();

        let config = siem_configs::ActiveModel {
            id: Set(id.clone()),
            org_id: Set(org_id.to_string()),
            name: Set(name.to_string()),
            provider: Set(provider_type.to_string()),
            endpoint_url: Set(endpoint_url.to_string()),
            api_key: Set(api_key),
            auth_header: Set(auth_header),
            batch_size: Set(batch_size.unwrap_or(100).to_string()),
            enabled: Set(true),
            last_successful_batch_at: Set(None),
            last_processed_log_id: Set(None),
            failure_count: Set(0),
            created_at: Set(now.clone()),
            updated_at: Set(now),
        };

        match db {
            DB::Conn(conn) => config.insert(conn).await?,
            DB::Tx(tx) => config.insert(tx).await?,
        };

        tracing::info!(
            siem_config_id = %id,
            org_id = %org_id,
            provider = %provider_type,
            "SIEM configuration created"
        );

        Ok(id)
    }

    /// Get SIEM configuration by ID
    pub async fn get_by_id(db: DB<'_>, id: &str) -> Result<Option<siem_configs::Model>> {
        let found = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        Ok(found)
    }

    /// Get all enabled SIEM configurations
    pub async fn get_enabled_configs(db: &DatabaseConnection) -> Result<Vec<siem_configs::Model>> {
        let configs = siem_configs::Entity::find()
            .filter(siem_configs::Column::Enabled.eq(true))
            .order_by_asc(siem_configs::Column::OrgId)
            .all(db)
            .await?;

        Ok(configs)
    }

    /// List SIEM configurations for an organization
    pub async fn list_by_org(
        db: &DatabaseConnection,
        org_id: &str,
    ) -> Result<Vec<siem_configs::Model>> {
        let configs = siem_configs::Entity::find()
            .filter(siem_configs::Column::OrgId.eq(org_id))
            .order_by_asc(siem_configs::Column::Name)
            .all(db)
            .await?;

        Ok(configs)
    }

    /// Update SIEM configuration
    pub async fn update(
        db: DB<'_>,
        id: &str,
        name: Option<String>,
        endpoint_url: Option<String>,
        api_key: Option<Option<String>>,
        auth_header: Option<Option<String>>,
        batch_size: Option<i32>,
        enabled: Option<bool>,
    ) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let mut active_model: siem_configs::ActiveModel = found
            .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?
            .into();

        if let Some(name) = name {
            active_model.name = Set(name);
        }
        if let Some(endpoint_url) = endpoint_url {
            active_model.endpoint_url = Set(endpoint_url);
        }
        if let Some(api_key) = api_key {
            active_model.api_key = Set(api_key);
        }
        if let Some(auth_header) = auth_header {
            active_model.auth_header = Set(auth_header);
        }
        if let Some(batch_size) = batch_size {
            active_model.batch_size = Set(batch_size.to_string());
        }
        if let Some(enabled) = enabled {
            active_model.enabled = Set(enabled);
        }

        active_model.updated_at = Set(Utc::now().naive_utc());

        match db {
            DB::Conn(conn) => active_model.update(conn).await?,
            DB::Tx(tx) => active_model.update(tx).await?,
        };

        tracing::info!(
            siem_config_id = %id,
            "SIEM configuration updated"
        );

        Ok(())
    }

    /// Delete SIEM configuration
    pub async fn delete(db: DB<'_>, id: &str) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let config =
            found.ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

        let config: siem_configs::ActiveModel = config.into();
        match db {
            DB::Conn(conn) => config.delete(conn).await?,
            DB::Tx(tx) => config.delete(tx).await?,
        };

        tracing::info!(
            siem_config_id = %id,
            "SIEM configuration deleted"
        );

        Ok(())
    }

    /// Update last successful batch timestamp and processed log ID
    pub async fn update_last_successful_batch(
        db: DB<'_>,
        id: &str,
        last_log_id: Option<String>,
    ) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let mut active_model: siem_configs::ActiveModel = found
            .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?
            .into();

        let now = Utc::now().naive_utc();
        active_model.last_successful_batch_at = Set(Some(now.clone()));
        active_model.last_processed_log_id = Set(last_log_id);
        active_model.failure_count = Set(0);
        active_model.updated_at = Set(now);

        match db {
            DB::Conn(conn) => active_model.update(conn).await?,
            DB::Tx(tx) => active_model.update(tx).await?,
        };

        Ok(())
    }

    /// Increment failure count for a SIEM configuration
    pub async fn increment_failure_count(db: DB<'_>, id: &str) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let mut active_model: siem_configs::ActiveModel = found
            .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?
            .into();

        let current_failures = match &active_model.failure_count {
            sea_orm::ActiveValue::Set(value) => *value,
            sea_orm::ActiveValue::Unchanged(value) => *value,
            _ => 0,
        };

        active_model.failure_count = Set(current_failures + 1);
        active_model.updated_at = Set(Utc::now().naive_utc());

        match db {
            DB::Conn(conn) => active_model.update(conn).await?,
            DB::Tx(tx) => active_model.update(tx).await?,
        };

        tracing::warn!(
            siem_config_id = %id,
            failure_count = current_failures + 1,
            "SIEM configuration failure count incremented"
        );

        Ok(())
    }

    /// Disable SIEM configuration after repeated failures
    pub async fn disable_after_failures(db: DB<'_>, id: &str, threshold: i32) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let mut active_model: siem_configs::ActiveModel = found
            .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?
            .into();

        let current_failures = match &active_model.failure_count {
            sea_orm::ActiveValue::Set(value) => *value,
            sea_orm::ActiveValue::Unchanged(value) => *value,
            _ => 0,
        };

        if current_failures >= threshold {
            active_model.enabled = Set(false);
            active_model.updated_at = Set(Utc::now().naive_utc());

            match db {
                DB::Conn(conn) => active_model.update(conn).await?,
                DB::Tx(tx) => active_model.update(tx).await?,
            };

            tracing::error!(
                siem_config_id = %id,
                failure_count = current_failures,
                "SIEM configuration disabled after repeated failures"
            );
        }

        Ok(())
    }
}
