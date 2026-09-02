//! SIEM Configuration Store
//!
//! Manages SIEM integration configurations for organizations.
//! Supports Datadog, Splunk, Elastic, and custom SIEM providers.

use crate::db::DB;
use crate::entities::siem_configs;
use crate::error::{AppError, Result};
use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};

pub struct SiemConfigStore;

impl SiemConfigStore {
    /// Create a new SIEM configuration
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        id: &str,
        org_id: &str,
        name: &str,
        provider_type: &str,
        endpoint_url: &str,
        api_key: Option<String>,
        auth_header: Option<String>,
        batch_size: Option<i32>,
    ) -> Result<String> {
        let now = Utc::now().naive_utc();

        let config = siem_configs::ActiveModel {
            id: Set(id.to_string()),
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
            created_at: Set(now),
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

        Ok(id.to_string())
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
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        db: DB<'_>,
        org_id: &str,
        id: &str,
        name: Option<String>,
        endpoint_url: Option<String>,
        api_key: Option<Option<String>>,
        auth_header: Option<Option<String>>,
        batch_size: Option<i32>,
        enabled: Option<bool>,
    ) -> Result<()> {
        let mut active_model = siem_configs::ActiveModel {
            updated_at: Set(Utc::now().naive_utc()),
            ..Default::default()
        };

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

        let result = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::update_many()
                    .set(active_model)
                    .filter(siem_configs::Column::Id.eq(id))
                    .filter(siem_configs::Column::OrgId.eq(org_id))
                    .exec(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::update_many()
                    .set(active_model)
                    .filter(siem_configs::Column::Id.eq(id))
                    .filter(siem_configs::Column::OrgId.eq(org_id))
                    .exec(tx)
                    .await?
            }
        };
        if result.rows_affected == 0 {
            return Err(AppError::NotFound(
                "SIEM configuration not found".to_string(),
            ));
        }

        tracing::info!(
            siem_config_id = %id,
            "SIEM configuration updated"
        );

        Ok(())
    }

    /// Delete SIEM configuration
    pub async fn delete(db: DB<'_>, org_id: &str, id: &str) -> Result<()> {
        let result = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::delete_many()
                    .filter(siem_configs::Column::Id.eq(id))
                    .filter(siem_configs::Column::OrgId.eq(org_id))
                    .exec(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::delete_many()
                    .filter(siem_configs::Column::Id.eq(id))
                    .filter(siem_configs::Column::OrgId.eq(org_id))
                    .exec(tx)
                    .await?
            }
        };
        if result.rows_affected == 0 {
            return Err(AppError::NotFound(
                "SIEM configuration not found".to_string(),
            ));
        }

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
        let now = Utc::now().naive_utc();
        let active_model = siem_configs::ActiveModel {
            last_successful_batch_at: Set(Some(now)),
            last_processed_log_id: Set(last_log_id),
            failure_count: Set(0),
            updated_at: Set(now),
            ..Default::default()
        };

        let result = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::update_many()
                    .set(active_model)
                    .filter(siem_configs::Column::Id.eq(id))
                    .exec(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::update_many()
                    .set(active_model)
                    .filter(siem_configs::Column::Id.eq(id))
                    .exec(tx)
                    .await?
            }
        };
        if result.rows_affected == 0 {
            return Err(AppError::NotFound(
                "SIEM configuration not found".to_string(),
            ));
        }

        Ok(())
    }

    /// Increment failure count for a SIEM configuration
    pub async fn increment_failure_count(db: DB<'_>, id: &str) -> Result<()> {
        let result = match db {
            DB::Conn(conn) => {
                siem_configs::Entity::update_many()
                    .col_expr(
                        siem_configs::Column::FailureCount,
                        Expr::col(siem_configs::Column::FailureCount).add(1),
                    )
                    .col_expr(
                        siem_configs::Column::UpdatedAt,
                        Expr::value(Utc::now().naive_utc()),
                    )
                    .filter(siem_configs::Column::Id.eq(id))
                    .exec(conn)
                    .await?
            }
            DB::Tx(tx) => {
                siem_configs::Entity::update_many()
                    .col_expr(
                        siem_configs::Column::FailureCount,
                        Expr::col(siem_configs::Column::FailureCount).add(1),
                    )
                    .col_expr(
                        siem_configs::Column::UpdatedAt,
                        Expr::value(Utc::now().naive_utc()),
                    )
                    .filter(siem_configs::Column::Id.eq(id))
                    .exec(tx)
                    .await?
            }
        };
        if result.rows_affected == 0 {
            return Err(AppError::NotFound(
                "SIEM configuration not found".to_string(),
            ));
        }

        tracing::warn!(
            siem_config_id = %id,
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

#[cfg(test)]
mod tests {
    use super::*;

    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, DatabaseConnection};
    use uuid::Uuid;

    async fn setup_db() -> (DatabaseConnection, String) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner_id = crate::test_support::insert_user(&db, None).await;
        let org_id = crate::test_support::insert_org(&db, &owner_id).await;
        (db, org_id)
    }

    #[tokio::test]
    async fn siem_config_mutations_are_org_scoped_and_preserve_results() {
        let (db, org_id) = setup_db().await;
        let other_owner = crate::test_support::insert_user(&db, None).await;
        let other_org_id = crate::test_support::insert_org(&db, &other_owner).await;
        let config_id = SiemConfigStore::create(
            DB::Conn(&db),
            "siem-config-test",
            &org_id,
            "Primary",
            "custom",
            "https://siem.example.com",
            Some("secret".to_string()),
            None,
            Some(100),
        )
        .await
        .expect("create siem config");

        assert!(matches!(
            SiemConfigStore::update(
                DB::Conn(&db),
                &other_org_id,
                &config_id,
                Some("Cross tenant".to_string()),
                None,
                Some(Some("stolen-secret".to_string())),
                None,
                None,
                Some(false),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            SiemConfigStore::delete(DB::Conn(&db), &other_org_id, &config_id).await,
            Err(AppError::NotFound(_))
        ));
        let preserved = SiemConfigStore::get_by_id(DB::Conn(&db), &config_id)
            .await
            .expect("load protected config")
            .expect("config remains");
        assert_eq!(preserved.org_id, org_id);
        assert_eq!(preserved.name, "Primary");
        assert_eq!(preserved.api_key.as_deref(), Some("secret"));
        assert!(preserved.enabled);

        SiemConfigStore::update(
            DB::Conn(&db),
            &org_id,
            &config_id,
            Some("Renamed".to_string()),
            None,
            Some(Some("new-secret".to_string())),
            Some(Some("Authorization: Bearer test".to_string())),
            Some(250),
            Some(false),
        )
        .await
        .expect("update config");
        SiemConfigStore::increment_failure_count(DB::Conn(&db), &config_id)
            .await
            .expect("increment failure once");
        SiemConfigStore::increment_failure_count(DB::Conn(&db), &config_id)
            .await
            .expect("increment failure twice");

        let updated = SiemConfigStore::get_by_id(DB::Conn(&db), &config_id)
            .await
            .expect("load config")
            .expect("config exists");
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.api_key.as_deref(), Some("new-secret"));
        assert_eq!(
            updated.auth_header.as_deref(),
            Some("Authorization: Bearer test")
        );
        assert_eq!(updated.batch_size, "250");
        assert!(!updated.enabled);
        assert_eq!(updated.failure_count, 2);

        SiemConfigStore::update_last_successful_batch(
            DB::Conn(&db),
            &config_id,
            Some("log-123".to_string()),
        )
        .await
        .expect("mark successful batch");
        let reset = SiemConfigStore::get_by_id(DB::Conn(&db), &config_id)
            .await
            .expect("load reset config")
            .expect("config exists after reset");
        assert_eq!(reset.failure_count, 0);
        assert_eq!(reset.last_processed_log_id.as_deref(), Some("log-123"));
        assert!(reset.last_successful_batch_at.is_some());

        SiemConfigStore::delete(DB::Conn(&db), &org_id, &config_id)
            .await
            .expect("delete config");
        assert!(SiemConfigStore::get_by_id(DB::Conn(&db), &config_id)
            .await
            .expect("load deleted config")
            .is_none());
    }

    #[tokio::test]
    async fn siem_config_single_statement_mutations_report_missing_rows() {
        let (db, org_id) = setup_db().await;
        let missing_id = Uuid::new_v4().to_string();

        assert!(matches!(
            SiemConfigStore::update(
                DB::Conn(&db),
                &org_id,
                &missing_id,
                Some("Missing".to_string()),
                None,
                None,
                None,
                None,
                None,
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            SiemConfigStore::increment_failure_count(DB::Conn(&db), &missing_id).await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            SiemConfigStore::update_last_successful_batch(DB::Conn(&db), &missing_id, None).await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            SiemConfigStore::delete(DB::Conn(&db), &org_id, &missing_id).await,
            Err(AppError::NotFound(_))
        ));
    }
}
