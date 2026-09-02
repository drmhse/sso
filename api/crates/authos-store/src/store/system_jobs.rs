use crate::db::DB;
use crate::entities::prelude::SystemJobs;
use crate::entities::system_jobs;
use crate::error::Result;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    FromQueryResult, IntoActiveModel, QueryFilter, QuerySelect, Set,
};
use std::collections::HashMap;
use uuid::Uuid;

pub struct SystemJobStore;

#[derive(Debug, FromQueryResult)]
struct JobStatusCount {
    status: String,
    count: i64,
}

impl SystemJobStore {
    /// Create a new job in the queue
    pub async fn create_job(
        db: DB<'_>,
        job_type: &str,
        payload: &str,
        priority: i32,
        max_retries: i32,
        scheduled_for: Option<chrono::DateTime<Utc>>,
    ) -> Result<String> {
        let job_id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();
        let scheduled_time = scheduled_for.unwrap_or_else(Utc::now).naive_utc();

        let job = system_jobs::ActiveModel {
            id: Set(job_id.clone()),
            job_type: Set(job_type.to_string()),
            payload: Set(payload.to_string()),
            status: Set("pending".to_string()),
            priority: Set(priority),
            max_retries: Set(max_retries),
            attempt_count: Set(0),
            scheduled_for: Set(scheduled_time),
            last_attempt_at: Set(None),
            completed_at: Set(None),
            failed_at: Set(None),
            error_message: Set(None),
            worker_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };

        job.insert(&db).await?;

        Ok(job_id)
    }

    /// Count jobs grouped by status in one query.
    pub async fn count_by_statuses(db: DB<'_>, statuses: &[&str]) -> Result<HashMap<String, i64>> {
        if statuses.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = SystemJobs::find()
            .filter(system_jobs::Column::Status.is_in(statuses.iter().copied()))
            .select_only()
            .column(system_jobs::Column::Status)
            .column_as(system_jobs::Column::Id.count(), "count")
            .group_by(system_jobs::Column::Status)
            .into_model::<JobStatusCount>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.status, row.count))
            .collect())
    }

    /// Atomically claim the next available job for a worker.
    /// Uses SeaORM's lock_with_behavior for database-agnostic locking.
    ///
    /// # Locking behavior:
    /// - **PostgreSQL/MySQL**: Uses `SELECT ... FOR UPDATE SKIP LOCKED` via SeaORM
    /// - **SQLite**: Uses BEGIN IMMEDIATE with optimistic locking (no SKIP LOCKED support)
    ///
    /// Returns `None` if no jobs are available.
    pub async fn claim_next_job(
        db: &DatabaseConnection,
        #[cfg(feature = "db_sqlite")] db_writer: &DatabaseConnection,
        worker_id: &str,
    ) -> Result<Option<system_jobs::Model>> {
        use sea_orm::{
            sea_query::LockBehavior, sea_query::LockType, QueryFilter, QueryOrder, QuerySelect,
            TransactionTrait,
        };

        let db_backend = db.get_database_backend();
        let is_sqlite = matches!(db_backend, sea_orm::DatabaseBackend::Sqlite);

        // Retry logic for SQLite database locked errors
        let max_retries = 25u32;
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            let now = Utc::now().naive_utc();

            // SQLite takes the write lock upfront with BEGIN IMMEDIATE on the
            // dedicated single-connection writer pool; other backends use the
            // shared pool and ordinary transaction semantics.
            let txn = match if is_sqlite {
                #[cfg(feature = "db_sqlite")]
                {
                    db_writer.begin().await
                }
                #[cfg(not(feature = "db_sqlite"))]
                {
                    unreachable!("SQLite feature not enabled")
                }
            } else {
                db.begin().await
            } {
                Ok(txn) => txn,
                Err(e) => {
                    if crate::error::is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            attempt = attempts,
                            phase = "begin",
                            "Job claim transaction contention, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            // Find the next available job with appropriate locking
            let query = SystemJobs::find()
                .filter(system_jobs::Column::Status.eq("pending"))
                .filter(system_jobs::Column::ScheduledFor.lte(now))
                .order_by_desc(system_jobs::Column::Priority)
                .order_by_asc(system_jobs::Column::CreatedAt)
                .limit(1);

            // Apply FOR UPDATE SKIP LOCKED for PostgreSQL and MySQL
            // SQLite will use optimistic locking via status check in update
            let job = match if is_sqlite {
                #[cfg(feature = "db_sqlite")]
                {
                    query.one(&txn).await
                }
                #[cfg(not(feature = "db_sqlite"))]
                {
                    unreachable!("SQLite feature not enabled")
                }
            } else {
                // Use lock_with_behavior for FOR UPDATE SKIP LOCKED
                query
                    .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
                    .one(&txn)
                    .await
            } {
                Ok(j) => j,
                Err(e) => {
                    // Rollback for SQLite
                    // Rollback using transaction
                    let _ = txn.rollback().await;
                    if crate::error::is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            attempt = attempts,
                            phase = "query",
                            "Job claim query contention, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            let job = match job {
                Some(j) => j,
                None => {
                    // Rollback and return
                    // Rollback and return
                    let _ = txn.rollback().await;
                    return Ok(None);
                }
            };

            // Update the job to "processing" status
            // For SQLite: include status check to handle race conditions
            let update_result = match if is_sqlite {
                // SQLite optimistic locking: only update if still "pending"
                system_jobs::Entity::update_many()
                    .col_expr(
                        system_jobs::Column::Status,
                        sea_orm::sea_query::Expr::value("processing"),
                    )
                    .col_expr(
                        system_jobs::Column::WorkerId,
                        sea_orm::sea_query::Expr::value(worker_id.to_string()),
                    )
                    .col_expr(
                        system_jobs::Column::LastAttemptAt,
                        sea_orm::sea_query::Expr::value(now),
                    )
                    .col_expr(
                        system_jobs::Column::AttemptCount,
                        sea_orm::sea_query::Expr::col(system_jobs::Column::AttemptCount)
                            .add(sea_orm::sea_query::Expr::value(1)),
                    )
                    .col_expr(
                        system_jobs::Column::UpdatedAt,
                        sea_orm::sea_query::Expr::value(now),
                    )
                    .filter(system_jobs::Column::Id.eq(&job.id))
                    .filter(system_jobs::Column::Status.eq("pending")) // Optimistic lock
                    .exec(&txn)
                    .await
            } else {
                // PostgreSQL/MySQL: lock_with_behavior already locked the row
                system_jobs::Entity::update_many()
                    .col_expr(
                        system_jobs::Column::Status,
                        sea_orm::sea_query::Expr::value("processing"),
                    )
                    .col_expr(
                        system_jobs::Column::WorkerId,
                        sea_orm::sea_query::Expr::value(worker_id.to_string()),
                    )
                    .col_expr(
                        system_jobs::Column::LastAttemptAt,
                        sea_orm::sea_query::Expr::value(now),
                    )
                    .col_expr(
                        system_jobs::Column::AttemptCount,
                        sea_orm::sea_query::Expr::col(system_jobs::Column::AttemptCount)
                            .add(sea_orm::sea_query::Expr::value(1)),
                    )
                    .col_expr(
                        system_jobs::Column::UpdatedAt,
                        sea_orm::sea_query::Expr::value(now),
                    )
                    .filter(system_jobs::Column::Id.eq(&job.id))
                    .exec(&txn)
                    .await
            } {
                Ok(r) => r,
                Err(e) => {
                    // Rollback for SQLite
                    // Rollback
                    let _ = txn.rollback().await;
                    if crate::error::is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            attempt = attempts,
                            phase = "update",
                            "Job claim update contention, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            // Check if update succeeded (for SQLite optimistic locking)
            if update_result.rows_affected == 0 {
                // Another worker claimed this job, retry
                let _ = txn.rollback().await;
                return Ok(None);
            }

            // Fetch the updated job
            let updated_job = match if is_sqlite {
                #[cfg(feature = "db_sqlite")]
                #[cfg(feature = "db_sqlite")]
                {
                    SystemJobs::find_by_id(&job.id).one(&txn).await
                }
                #[cfg(not(feature = "db_sqlite"))]
                {
                    unreachable!("SQLite feature not enabled")
                }
            } else {
                SystemJobs::find_by_id(&job.id).one(&txn).await
            } {
                Ok(j) => j,
                Err(e) => {
                    // Rollback for SQLite
                    // Rollback
                    let _ = txn.rollback().await;
                    if crate::error::is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            attempt = attempts,
                            phase = "fetch",
                            "Job claim fetch contention, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            // Commit transaction
            let commit_result = txn.commit().await;

            match commit_result {
                Ok(_) => {
                    if let Some(ref j) = updated_job {
                        tracing::debug!(
                            job_id = %j.id,
                            worker_id = %worker_id,
                            db_backend = ?db_backend,
                            "Job claimed atomically via SeaORM"
                        );
                    }
                    return Ok(updated_job);
                }
                Err(e) => {
                    if crate::error::is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            attempt = attempts,
                            phase = "commit",
                            "Job claim commit contention, retrying entire transaction"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }
    }

    /// Get pending jobs ready to be processed
    #[deprecated(
        since = "0.2.0",
        note = "Use claim_next_job for atomic job claiming. This method has race conditions."
    )]
    pub async fn get_pending_jobs(db: DB<'_>, limit: u64) -> Result<Vec<system_jobs::Model>> {
        use sea_orm::{QueryFilter, QueryOrder};

        let now = Utc::now().naive_utc();

        let jobs = SystemJobs::find()
            .filter(system_jobs::Column::Status.eq("pending"))
            .filter(system_jobs::Column::ScheduledFor.lte(now))
            .order_by_desc(system_jobs::Column::Priority)
            .order_by_asc(system_jobs::Column::CreatedAt)
            .limit(limit)
            .all(&db)
            .await?;

        Ok(jobs)
    }

    /// Mark job as processing (for use with claim_next_job fallback)
    #[deprecated(
        since = "0.2.0",
        note = "Use claim_next_job which atomically marks as processing."
    )]
    pub async fn mark_as_processing(db: DB<'_>, job_id: &str) -> Result<()> {
        let now = Utc::now().naive_utc();

        let job = SystemJobs::find_by_id(job_id)
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Job not found".to_string()))?;

        let mut job: system_jobs::ActiveModel = job.into_active_model();

        let current_attempt = match &job.attempt_count {
            sea_orm::ActiveValue::Set(value) => *value,
            sea_orm::ActiveValue::Unchanged(value) => *value,
            _ => 0,
        };

        job.status = Set("processing".to_string());
        job.last_attempt_at = Set(Some(now));
        job.attempt_count = Set(current_attempt + 1);
        job.updated_at = Set(now);

        job.update(&db).await?;

        Ok(())
    }

    /// Mark job as completed
    pub async fn mark_as_completed(db: DB<'_>, job_id: &str) -> Result<()> {
        let now = Utc::now().naive_utc();

        let job = SystemJobs::find_by_id(job_id)
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Job not found".to_string()))?;

        let mut job: system_jobs::ActiveModel = job.into_active_model();
        job.status = Set("completed".to_string());
        job.completed_at = Set(Some(now));
        job.updated_at = Set(now);

        job.update(&db).await?;

        Ok(())
    }

    /// Mark job as failed
    pub async fn mark_as_failed(db: DB<'_>, job_id: &str, error_message: &str) -> Result<()> {
        let now = Utc::now().naive_utc();

        let job = SystemJobs::find_by_id(job_id)
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Job not found".to_string()))?;

        let attempt_count = job.attempt_count;
        let max_retries = job.max_retries;

        let mut job: system_jobs::ActiveModel = job.into_active_model();

        // If job is already failed or completed, don't overwrite it
        // This handles cases where we explicitly marked it as permanent failure but the worker loop calls mark_as_failed
        if let sea_orm::ActiveValue::Unchanged(status) = &job.status {
            if status == "failed" || status == "completed" {
                return Ok(());
            }
        } else if let sea_orm::ActiveValue::Set(status) = &job.status {
            if status == "failed" || status == "completed" {
                return Ok(());
            }
        }

        // Check if we should retry
        if attempt_count < max_retries {
            // Retry with exponential backoff
            let retry_delay_seconds = 2_i64.pow(attempt_count as u32) * 5; // 5s, 10s, 20s, 40s, etc.
            let scheduled_for = Utc::now() + chrono::Duration::seconds(retry_delay_seconds);

            job.status = Set("pending".to_string());
            job.scheduled_for = Set(scheduled_for.naive_utc());
            job.error_message = Set(Some(error_message.to_string()));
            job.worker_id = Set(None); // Clear worker_id for retry
        } else {
            // Max retries reached, mark as permanently failed
            job.status = Set("failed".to_string());
            job.failed_at = Set(Some(now));
            job.error_message = Set(Some(error_message.to_string()));
        }

        job.updated_at = Set(now);
        job.update(&db).await?;

        Ok(())
    }

    /// Delete old completed jobs
    pub async fn cleanup_old_jobs(db: DB<'_>, days_to_keep: i64) -> Result<u64> {
        use sea_orm::QueryFilter;
        let cutoff_date = Utc::now() - chrono::Duration::days(days_to_keep);
        let cutoff_datetime = cutoff_date.naive_utc();

        let result = SystemJobs::delete_many()
            .filter(system_jobs::Column::Status.eq("completed"))
            .filter(system_jobs::Column::CompletedAt.lte(cutoff_datetime))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Mark job as permanently failed (skipping remaining retries)
    pub async fn mark_as_failed_permanently(
        db: DB<'_>,
        job_id: &str,
        error_message: &str,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        let job = SystemJobs::find_by_id(job_id)
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Job not found".to_string()))?;

        let mut job: system_jobs::ActiveModel = job.into_active_model();

        job.status = Set("failed".to_string());
        job.failed_at = Set(Some(now));
        job.error_message = Set(Some(error_message.to_string()));
        job.worker_id = Set(None); // Clear worker_id
        job.updated_at = Set(now);

        job.update(&db).await?;

        Ok(())
    }
}

/// Calculate retry delay with exponential backoff and jitter
fn calculate_retry_delay(attempt: u32) -> u64 {
    let base_delay_ms = 20 * (1 << attempt.min(8)); // 40ms... up to ~5120ms
    let jitter_ms = rand::random::<u64>() % (base_delay_ms / 2);
    base_delay_ms + jitter_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn count_by_statuses_groups_job_statuses_in_one_result() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let pending = SystemJobStore::create_job(DB::Conn(&db), "test", "{}", 0, 3, None)
            .await
            .expect("create pending job");
        let processing = SystemJobStore::create_job(DB::Conn(&db), "test", "{}", 0, 3, None)
            .await
            .expect("create processing job");
        let failed = SystemJobStore::create_job(DB::Conn(&db), "test", "{}", 0, 3, None)
            .await
            .expect("create failed job");
        let completed = SystemJobStore::create_job(DB::Conn(&db), "test", "{}", 0, 3, None)
            .await
            .expect("create completed job");

        #[allow(deprecated)]
        SystemJobStore::mark_as_processing(DB::Conn(&db), &processing)
            .await
            .expect("mark processing");
        SystemJobStore::mark_as_failed_permanently(DB::Conn(&db), &failed, "failed")
            .await
            .expect("mark failed");
        SystemJobStore::mark_as_completed(DB::Conn(&db), &completed)
            .await
            .expect("mark completed");

        let counts =
            SystemJobStore::count_by_statuses(DB::Conn(&db), &["pending", "processing", "failed"])
                .await
                .expect("count statuses");

        assert_eq!(*counts.get("pending").unwrap_or(&0), 1);
        assert_eq!(*counts.get("processing").unwrap_or(&0), 1);
        assert_eq!(*counts.get("failed").unwrap_or(&0), 1);
        assert_eq!(*counts.get("completed").unwrap_or(&0), 0);
        assert!(!pending.is_empty());
    }

    #[tokio::test]
    async fn failed_jobs_retry_then_stop_at_the_configured_bound() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let job_id = SystemJobStore::create_job(DB::Conn(&db), "test", "{}", 0, 2, None)
            .await
            .expect("create job");

        #[allow(deprecated)]
        SystemJobStore::mark_as_processing(DB::Conn(&db), &job_id)
            .await
            .expect("claim first attempt");
        SystemJobStore::mark_as_failed(DB::Conn(&db), &job_id, "transient")
            .await
            .expect("schedule retry");
        let retry = SystemJobs::find_by_id(&job_id)
            .one(&db)
            .await
            .expect("load retry")
            .expect("retry exists");
        assert_eq!(retry.status, "pending");
        assert_eq!(retry.attempt_count, 1);
        assert_eq!(retry.worker_id, None);
        assert!(retry.failed_at.is_none());

        #[allow(deprecated)]
        SystemJobStore::mark_as_processing(DB::Conn(&db), &job_id)
            .await
            .expect("claim final attempt");
        SystemJobStore::mark_as_failed(DB::Conn(&db), &job_id, "still failing")
            .await
            .expect("stop retries");
        let failed = SystemJobs::find_by_id(&job_id)
            .one(&db)
            .await
            .expect("load failure")
            .expect("failure exists");
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.attempt_count, 2);
        assert_eq!(failed.error_message.as_deref(), Some("still failing"));
        assert!(failed.failed_at.is_some());
    }
}
