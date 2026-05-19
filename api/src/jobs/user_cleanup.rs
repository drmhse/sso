#![allow(dead_code)]

use crate::store::{users::UserStore, DB};
use chrono::{Duration, Utc};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

pub struct UserCleanupJob {
    db: DatabaseConnection,
}

impl UserCleanupJob {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn start(self) {
        // Run every 8640x the base interval (default: every 24 hours)
        let mut interval = tokio::time::interval(super::get_cleanup_job_interval(8640));

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_soft_deleted_users().await {
                tracing::error!("User cleanup job failed: {}", e);
            }
        }
    }

    /// Permanently deletes users that were soft deleted (anonymized) more than 30 days ago
    /// This fulfills GDPR "Right to be Forgotten" requirements
    async fn cleanup_soft_deleted_users(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting user cleanup job for GDPR compliance");

        let cutoff_date = Utc::now() - Duration::days(30);
        let cutoff_naive = cutoff_date.naive_utc();

        // Find users who were soft deleted more than 30 days ago
        use crate::entities::users;
        use sea_orm::QueryOrder;

        let users_to_delete = users::Entity::find()
            .filter(users::Column::DeletedAt.is_not_null())
            .filter(users::Column::DeletedAt.lt(cutoff_naive))
            .order_by_asc(users::Column::DeletedAt)
            .all(&self.db)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let total_users = users_to_delete.len();

        if total_users == 0 {
            tracing::info!("No users to clean up (no users older than 30 days soft-deleted)");
            return Ok(());
        }

        tracing::info!(
            "Found {} users to permanently delete (soft deleted before {})",
            total_users,
            cutoff_date.to_rfc3339()
        );

        // Process users in batches to avoid long-running transactions
        const BATCH_SIZE: usize = 100;
        let mut deleted_count = 0;
        let mut error_count = 0;

        for batch in users_to_delete.chunks(BATCH_SIZE) {
            for user in batch {
                match UserStore::delete(DB::Conn(&self.db), &user.id).await {
                    Ok(()) => {
                        deleted_count += 1;
                        tracing::debug!(
                            user_id = %user.id,
                            original_email = %user.email,
                            soft_deleted_at = ?user.deleted_at,
                            "Permanently deleted user"
                        );
                    }
                    Err(e) => {
                        error_count += 1;
                        tracing::error!(
                            user_id = %user.id,
                            error = %e,
                            "Failed to permanently delete user"
                        );
                    }
                }
            }

            // Small delay between batches to avoid overwhelming the database
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        tracing::info!(
            total_users_found = total_users,
            successfully_deleted = deleted_count,
            errors = error_count,
            "User cleanup job completed"
        );

        if error_count > 0 {
            tracing::warn!(
                errors = error_count,
                "Some users failed to be permanently deleted - they will be retried in the next run"
            );
        }

        Ok(())
    }

    /// For manual execution or testing - runs cleanup once and returns results
    pub async fn run_once(&self) -> Result<CleanupResults, Box<dyn std::error::Error>> {
        let cutoff_date = Utc::now() - Duration::days(30);
        let cutoff_naive = cutoff_date.naive_utc();

        use crate::entities::users;
        use sea_orm::QueryOrder;

        let users_to_delete = users::Entity::find()
            .filter(users::Column::DeletedAt.is_not_null())
            .filter(users::Column::DeletedAt.lt(cutoff_naive))
            .order_by_asc(users::Column::DeletedAt)
            .all(&self.db)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let total_users = users_to_delete.len();
        let mut deleted_count = 0;
        let mut error_count = 0;

        for user in users_to_delete {
            match UserStore::delete(DB::Conn(&self.db), &user.id).await {
                Ok(()) => {
                    deleted_count += 1;
                }
                Err(e) => {
                    error_count += 1;
                    tracing::error!(
                        user_id = %user.id,
                        error = %e,
                        "Failed to permanently delete user"
                    );
                }
            }
        }

        Ok(CleanupResults {
            users_found: total_users,
            successfully_deleted: deleted_count,
            errors: error_count,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CleanupResults {
    pub users_found: usize,
    pub successfully_deleted: usize,
    pub errors: usize,
}

impl CleanupResults {
    pub fn success_rate(&self) -> f64 {
        if self.users_found == 0 {
            1.0
        } else {
            self.successfully_deleted as f64 / self.users_found as f64
        }
    }

    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }
}
