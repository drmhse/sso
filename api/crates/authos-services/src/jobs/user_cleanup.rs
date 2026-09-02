use crate::db::DB;
use crate::store::users::UserStore;
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
            let batch_ids = batch.iter().map(|user| user.id.clone()).collect::<Vec<_>>();
            match UserStore::delete_by_ids(DB::Conn(&self.db), &batch_ids).await {
                Ok(rows_affected) => {
                    deleted_count += rows_affected as usize;
                    for user in batch {
                        tracing::debug!(
                            user_id = %user.id,
                            soft_deleted_at = ?user.deleted_at,
                            "Permanently deleted user"
                        );
                    }
                }
                Err(batch_error) => {
                    tracing::warn!(
                        error = %batch_error,
                        batch_size = batch.len(),
                        "Bulk user cleanup batch failed, falling back to per-user deletes"
                    );
                    for user in batch {
                        match UserStore::delete(DB::Conn(&self.db), &user.id).await {
                            Ok(()) => {
                                deleted_count += 1;
                                tracing::debug!(
                                    user_id = %user.id,
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

        for batch in users_to_delete.chunks(100) {
            let batch_ids = batch.iter().map(|user| user.id.clone()).collect::<Vec<_>>();
            match UserStore::delete_by_ids(DB::Conn(&self.db), &batch_ids).await {
                Ok(rows_affected) => {
                    deleted_count += rows_affected as usize;
                }
                Err(batch_error) => {
                    tracing::warn!(
                        error = %batch_error,
                        batch_size = batch.len(),
                        "Bulk user cleanup batch failed, falling back to per-user deletes"
                    );
                    for user in batch {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{prelude::Users, users};
    use chrono::Duration;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    /// Soft-deletes a user with a chosen deletion timestamp.
    async fn soft_delete_at(db: &DatabaseConnection, user_id: &str, when: chrono::DateTime<Utc>) {
        let user = Users::find_by_id(user_id)
            .one(db)
            .await
            .expect("find user")
            .expect("user exists");
        let mut active: users::ActiveModel = user.into();
        active.deleted_at = Set(Some(when.naive_utc()));
        active.update(db).await.expect("soft delete");
    }

    #[tokio::test]
    async fn run_once_reports_an_empty_queue() {
        let db = db().await;
        let job = UserCleanupJob::new(db.clone());

        let results = job.run_once().await.expect("run once");
        assert_eq!(results.users_found, 0);
        assert_eq!(results.successfully_deleted, 0);
        assert!(results.success_rate() == 1.0);
        assert!(!results.has_errors());
    }

    #[tokio::test]
    async fn only_users_soft_deleted_beyond_thirty_days_are_purged() {
        let db = db().await;
        let ancient = UserStore::create(DB::Conn(&db), "ancient@example.test", None, false)
            .await
            .expect("create ancient");
        let recent = UserStore::create(DB::Conn(&db), "recent@example.test", None, false)
            .await
            .expect("create recent");
        let live = UserStore::create(DB::Conn(&db), "live@example.test", None, false)
            .await
            .expect("create live");

        // Deleted 31 days ago: purged. Deleted 1 day ago: retained.
        soft_delete_at(&db, &ancient.id, Utc::now() - Duration::days(31)).await;
        soft_delete_at(&db, &recent.id, Utc::now() - Duration::days(1)).await;

        let job = UserCleanupJob::new(db.clone());
        let results = job.run_once().await.expect("run once");

        assert_eq!(
            results.users_found, 1,
            "only the ancient deletion qualifies"
        );
        assert_eq!(results.successfully_deleted, 1);
        assert!(!results.has_errors());

        assert!(
            Users::find_by_id(&ancient.id)
                .one(&db)
                .await
                .unwrap()
                .is_none(),
            "the GDPR-purged user must be gone entirely"
        );
        assert!(Users::find_by_id(&recent.id)
            .one(&db)
            .await
            .unwrap()
            .is_some());
        assert!(Users::find_by_id(&live.id)
            .one(&db)
            .await
            .unwrap()
            .is_some());

        // A second pass is a no-op.
        let again = job.run_once().await.expect("second run");
        assert_eq!(again.users_found, 0);
    }

    #[tokio::test]
    async fn success_rate_reflects_partial_failure_arithmetic() {
        let results = CleanupResults {
            users_found: 4,
            successfully_deleted: 3,
            errors: 1,
        };
        assert_eq!(results.success_rate(), 0.75);
        assert!(results.has_errors());
    }
}
