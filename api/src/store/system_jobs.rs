use crate::entities::prelude::SystemJobs;
use crate::entities::system_jobs;
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    IntoActiveModel, QuerySelect, Set,
};
use uuid::Uuid;

pub struct SystemJobStore;

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

            // For SQLite: Use raw BEGIN IMMEDIATE to acquire write lock upfront
            // with the dedicated writer connection
            // Start transaction
            // For SQLite: Use db_writer (single connection pool)
            // For others: Use db (shared pool)
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
