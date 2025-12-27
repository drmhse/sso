//! Log Streams Store
//!
//! Manages organization log streaming configurations for SIEM integration.

use crate::entities::log_streams;
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

pub struct LogStreamStore;

impl LogStreamStore {
    /// Create a new log stream configuration
    pub async fn create(
        db: DB<'_>,
        org_id: &str,
        name: &str,
        stream_type: &str,
        config_encrypted: Vec<u8>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();

        let log_stream = log_streams::ActiveModel {
            id: Set(id.clone()),
            org_id: Set(org_id.to_string()),
            name: Set(name.to_string()),
            stream_type: Set(stream_type.to_string()),
            config_encrypted: Set(config_encrypted),
            status: Set("active".to_string()),
            last_delivery_at: Set(None),
            failure_count: Set(0),
            created_at: Set(now.clone()),
            updated_at: Set(now),
        };

        match db {
            DB::Conn(conn) => log_stream.insert(conn).await?,
            DB::Tx(tx) => log_stream.insert(tx).await?,
        };

        tracing::info!(
            log_stream_id = %id,
            org_id = %org_id,
            name = %name,
            stream_type = %stream_type,
            "Log stream created"
        );

        Ok(id)
    }

    /// Get log stream by ID
    pub async fn get_by_id(db: DB<'_>, id: &str) -> Result<Option<log_streams::Model>> {
        let found = match db {
            DB::Conn(conn) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        Ok(found)
    }

    /// Find active log streams for an organization
    pub async fn find_active_by_org(
        db: &DatabaseConnection,
        org_id: &str,
    ) -> Result<Vec<log_streams::Model>> {
        let streams = log_streams::Entity::find()
            .filter(log_streams::Column::OrgId.eq(org_id))
            .filter(log_streams::Column::Status.eq("active"))
            .order_by_asc(log_streams::Column::Name)
            .all(db)
            .await?;

        Ok(streams)
    }

    /// Update log stream configuration
    pub async fn update(
        db: DB<'_>,
        id: &str,
        name: Option<String>,
        config_encrypted: Option<Vec<u8>>,
        status: Option<String>,
    ) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let mut active_model: log_streams::ActiveModel = found
            .ok_or_else(|| AppError::NotFound("Log stream not found".to_string()))?
            .into();

        if let Some(name) = name {
            active_model.name = Set(name);
        }
        if let Some(config_encrypted) = config_encrypted {
            active_model.config_encrypted = Set(config_encrypted);
        }
        if let Some(status) = status {
            active_model.status = Set(status);
        }

        active_model.updated_at = Set(Utc::now().naive_utc());

        match db {
            DB::Conn(conn) => active_model.update(conn).await?,
            DB::Tx(tx) => active_model.update(tx).await?,
        };

        tracing::info!(
            log_stream_id = %id,
            "Log stream updated"
        );

        Ok(())
    }

    /// Update delivery status and timestamp
    pub async fn update_delivery_status(db: DB<'_>, id: &str, success: bool) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let mut active_model: log_streams::ActiveModel = found
            .ok_or_else(|| AppError::NotFound("Log stream not found".to_string()))?
            .into();

        if success {
            active_model.last_delivery_at = Set(Some(Utc::now().naive_utc()));
            active_model.failure_count = Set(0);
            active_model.status = Set("active".to_string());
        } else {
            let current_failures = match &active_model.failure_count {
                sea_orm::ActiveValue::Set(value) => *value,
                sea_orm::ActiveValue::Unchanged(value) => *value,
                _ => 0,
            };
            active_model.failure_count = Set(current_failures + 1);

            // Mark as error after 3 consecutive failures
            if current_failures + 1 >= 3 {
                active_model.status = Set("error".to_string());
            }
        }

        active_model.updated_at = Set(Utc::now().naive_utc());

        match db {
            DB::Conn(conn) => active_model.update(conn).await?,
            DB::Tx(tx) => active_model.update(tx).await?,
        };

        Ok(())
    }

    /// Delete log stream
    pub async fn delete(db: DB<'_>, id: &str) -> Result<()> {
        let found = match db {
            DB::Conn(conn) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(conn)
                    .await?
            }
            DB::Tx(tx) => {
                log_streams::Entity::find_by_id(id.to_string())
                    .one(tx)
                    .await?
            }
        };

        let log_stream =
            found.ok_or_else(|| AppError::NotFound("Log stream not found".to_string()))?;

        match db {
            DB::Conn(conn) => log_stream.delete(conn).await?,
            DB::Tx(tx) => log_stream.delete(tx).await?,
        };

        tracing::info!(
            log_stream_id = %id,
            "Log stream deleted"
        );

        Ok(())
    }

    /// List log streams for an organization with pagination
    pub async fn list_by_org(
        db: &DatabaseConnection,
        org_id: &str,
        page: u64,
        page_size: u64,
    ) -> Result<(Vec<log_streams::Model>, u64)> {
        let paginator = log_streams::Entity::find()
            .filter(log_streams::Column::OrgId.eq(org_id))
            .order_by_asc(log_streams::Column::Name)
            .paginate(db, page_size);

        let total_pages = paginator.num_pages().await?;
        let streams = paginator.fetch_page(page).await?;

        Ok((streams, total_pages))
    }

    /// Reset failure count and reactivate a log stream
    pub async fn reactivate(db: DB<'_>, id: &str) -> Result<()> {
        Self::update(db, id, None, None, Some("active".to_string())).await?;

        tracing::info!(
            log_stream_id = %id,
            "Log stream reactivated"
        );

        Ok(())
    }
}
