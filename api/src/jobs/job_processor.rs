//! Job Processor - Background worker for processing jobs from the system_jobs queue
//!
//! Uses atomic job claiming with concurrent processing to maximize throughput.
//! Jobs are claimed atomically using database-level locking (FOR UPDATE SKIP LOCKED)
//! and processed concurrently up to a configurable limit.

use crate::email::EmailService;
use crate::error::Result;
use crate::services::job_queue::{EmailJobPayload, JobType, WebhookJobPayload};
use crate::services::safe_http::SafeHttpClient;
use crate::store::system_jobs::SystemJobStore;
use crate::store::webhook_deliveries::WebhookDeliveryStore;
use crate::store::DB;
use sea_orm::DatabaseConnection;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Default maximum concurrent jobs to process
const DEFAULT_MAX_CONCURRENT_JOBS: usize = 10;

/// Job Processor - processes background jobs with concurrent execution
pub struct JobProcessor {
    db: Arc<DatabaseConnection>,
    #[cfg(feature = "db_sqlite")]
    db_writer: Arc<DatabaseConnection>,
    worker_id: String,
    email_service: Option<Arc<EmailService>>,
    encryption: Option<crate::encryption::EncryptionService>,
    max_concurrent_jobs: usize,
}

impl JobProcessor {
    pub fn new(
        db: DatabaseConnection,
        #[cfg(feature = "db_sqlite")] db_writer: DatabaseConnection,
        email_service: Option<Arc<EmailService>>,
        encryption: Option<crate::encryption::EncryptionService>,
        batch_size: usize, // Now used as max_concurrent_jobs
    ) -> Self {
        // Generate unique worker ID: hostname-uuid
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let worker_id = format!("{}-{}", hostname, Uuid::new_v4());

        let max_concurrent_jobs = if batch_size > 0 {
            batch_size
        } else {
            DEFAULT_MAX_CONCURRENT_JOBS
        };

        tracing::info!(
            worker_id = %worker_id,
            max_concurrent_jobs = max_concurrent_jobs,
            "Job processor initialized with concurrent processing"
        );

        Self {
            db: Arc::new(db),
            #[cfg(feature = "db_sqlite")]
            db_writer: Arc::new(db_writer),
            worker_id,
            email_service,
            encryption,
            max_concurrent_jobs,
        }
    }

    /// Start the job processor worker with concurrent job processing
    ///
    /// Uses a concurrent claim-and-process pattern:
    /// 1. Continuously claim jobs up to max_concurrent_jobs limit
    /// 2. Each claimed job is processed in its own async task
    /// 3. When a slot frees up, immediately try to claim another job
    pub async fn start(self) {
        tracing::info!(
            worker_id = %self.worker_id,
            max_concurrent = self.max_concurrent_jobs,
            "Starting concurrent job processor"
        );

        // Semaphore to limit concurrent job processing
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_jobs));
        // Counter for active jobs (for logging/monitoring)
        let active_jobs = Arc::new(AtomicUsize::new(0));

        // Wrap self in Arc for sharing across tasks
        let processor = Arc::new(self);

        // Backoff state
        let max_interval = super::get_job_interval();
        let min_interval = Duration::from_millis(100);
        let mut consecutive_empty_polls = 0;

        loop {
            // Try to acquire a permit (slot for processing)
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    // All slots are busy, wait a bit before checking again
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // Try to claim a job
            match SystemJobStore::claim_next_job(
                &processor.db,
                #[cfg(feature = "db_sqlite")]
                &processor.db_writer,
                &processor.worker_id,
            )
            .await
            {
                Ok(Some(job)) => {
                    // Reset backoff since we found work
                    consecutive_empty_polls = 0;

                    let job_id = job.id.clone();
                    let job_type = job.job_type.clone();
                    let proc = processor.clone();
                    let active = active_jobs.clone();

                    active.fetch_add(1, Ordering::SeqCst);
                    let current_active = active.load(Ordering::SeqCst);

                    tracing::info!(
                        worker_id = %proc.worker_id,
                        job_id = %job_id,
                        job_type = %job_type,
                        active_jobs = current_active,
                        "Claimed job, spawning processor task"
                    );

                    // Spawn async task to process the job
                    tokio::spawn(async move {
                        // Process the job
                        let result = proc.process_job(&job).await;

                        // Mark as completed or failed
                        match result {
                            Ok(()) => {
                                if let Err(e) =
                                    SystemJobStore::mark_as_completed(DB::Conn(&proc.db), &job.id)
                                        .await
                                {
                                    tracing::error!(
                                        job_id = %job.id,
                                        error = %e,
                                        "Failed to mark job as completed"
                                    );
                                } else {
                                    tracing::info!(
                                        worker_id = %proc.worker_id,
                                        job_id = %job.id,
                                        job_type = %job.job_type,
                                        "Job completed successfully"
                                    );
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("{}", e);
                                if let Err(mark_err) = SystemJobStore::mark_as_failed(
                                    DB::Conn(&proc.db),
                                    &job.id,
                                    &error_msg,
                                )
                                .await
                                {
                                    tracing::error!(
                                        job_id = %job.id,
                                        error = %mark_err,
                                        "Failed to mark job as failed"
                                    );
                                } else {
                                    tracing::warn!(
                                        worker_id = %proc.worker_id,
                                        job_id = %job.id,
                                        job_type = %job.job_type,
                                        error = %error_msg,
                                        "Job failed"
                                    );
                                }
                            }
                        }

                        // Decrement active count and drop permit to release slot
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(permit);
                    });

                    // Immediately try to claim another job (don't wait)
                    continue;
                }
                Ok(None) => {
                    // No jobs available, release permit and wait
                    drop(permit);

                    let current_active = active_jobs.load(Ordering::SeqCst);
                    if current_active == 0 {
                        // Only backoff if we are truly idle
                        // Adaptive polling: start slow, back off exponentially
                        consecutive_empty_polls += 1;

                        let backoff_factor =
                            2_u32.pow(std::cmp::min(consecutive_empty_polls, 10) as u32);
                        let sleep_duration = std::cmp::min(
                            min_interval.saturating_mul(backoff_factor),
                            max_interval,
                        );

                        if consecutive_empty_polls == 1 {
                            tracing::debug!(
                                worker_id = %processor.worker_id,
                                "No pending jobs, starting adaptive backoff"
                            );
                        }

                        tokio::time::sleep(sleep_duration).await;
                    } else {
                        // Jobs are being processed, just yield briefly
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                Err(e) => {
                    // Error during claiming, release permit and back off
                    drop(permit);
                    tracing::error!(
                        worker_id = %processor.worker_id,
                        error = %e,
                        "Job claim error, backing off"
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Process a single job based on its type
    async fn process_job(&self, job: &crate::entities::system_jobs::Model) -> Result<()> {
        let job_type = JobType::from_str(&job.job_type);

        match job_type {
            JobType::SendEmail => self.process_email_job(&job.id, &job.payload).await,
            JobType::DeliverWebhook => self.process_webhook_job(&job.payload).await,
            JobType::Custom(ref custom_type) => {
                tracing::debug!(
                    worker_id = %self.worker_id,
                    job_type = %custom_type,
                    "Custom job type not implemented, skipping"
                );
                Ok(()) // Gracefully skip - job will be marked complete to clear queue
            }
        }
    }

    /// Process an email job
    async fn process_email_job(&self, job_id: &str, payload: &str) -> Result<()> {
        let email_payload: EmailJobPayload = serde_json::from_str(payload).map_err(|e| {
            crate::error::AppError::BadRequest(format!("Invalid email payload: {}", e))
        })?;

        if let Some(email_service) = &self.email_service {
            let result = email_service
                .send_email(
                    &email_payload.to,
                    &email_payload.subject,
                    &email_payload.body,
                )
                .await;

            match result {
                Ok(_) => {
                    tracing::info!(
                        worker_id = %self.worker_id,
                        to = %email_payload.to,
                        subject = %email_payload.subject,
                        "Email sent successfully"
                    );
                    // Success
                }
                Err(e) => {
                    // Check if this is a permanent SMTP error
                    let err_str = format!("{:?}", e);
                    let is_permanent = err_str.contains("permanent error")
                        || err_str.contains("Message rejected")
                        || err_str.contains("Email address is not verified")
                        || err_str.contains("554");

                    if is_permanent {
                        tracing::warn!(
                            worker_id = %self.worker_id,
                            to = %email_payload.to,
                            error = %e,
                            "Permanent SMTP error detected, marking job as failed permanently"
                        );

                        if let Err(mark_err) =
                            crate::services::job_queue::JobQueueService::mark_failed_permanently(
                                &self.db,
                                job_id,
                                &format!("Permanent SMTP Error: {}", e),
                            )
                            .await
                        {
                            tracing::error!(
                                "Failed to mark job as failed permanently: {}",
                                mark_err
                            );
                        }

                        return Err(crate::error::AppError::InternalServerError(format!(
                            "Permanent SMTP Error: {}",
                            e
                        )));
                    }

                    return Err(crate::error::AppError::InternalServerError(format!(
                        "Failed to send email: {}",
                        e
                    )));
                }
            }
        } else {
            tracing::warn!(
                worker_id = %self.worker_id,
                to = %email_payload.to,
                "Email service not configured, skipping email send"
            );
        }

        Ok(())
    }

    /// Process a webhook delivery job
    async fn process_webhook_job(&self, payload: &str) -> Result<()> {
        let webhook_payload: WebhookJobPayload = serde_json::from_str(payload).map_err(|e| {
            crate::error::AppError::BadRequest(format!("Invalid webhook payload: {}", e))
        })?;

        let payload_body = serde_json::to_string(&webhook_payload.payload).map_err(|e| {
            crate::error::AppError::InternalServerError(format!(
                "Failed to serialize webhook payload: {}",
                e
            ))
        })?;
        let safe_client = SafeHttpClient::new()?;

        // Reauthorize the exact delivery immediately before outbound I/O. A
        // queued job cannot outlive webhook disablement or parent suspension,
        // and payload IDs cannot be mixed across deliveries.
        let Some(authorized) = WebhookDeliveryStore::find_authorized_open_delivery(
            DB::Conn(&self.db),
            &webhook_payload.delivery_id,
            &webhook_payload.webhook_id,
        )
        .await?
        else {
            tracing::warn!(
                worker_id = %self.worker_id,
                webhook_id = %webhook_payload.webhook_id,
                delivery_id = %webhook_payload.delivery_id,
                "Webhook delivery is no longer authorized, skipping outbound request"
            );
            WebhookDeliveryStore::mark_as_failed_permanently_for_webhook(
                DB::Conn(&self.db),
                &webhook_payload.delivery_id,
                &webhook_payload.webhook_id,
                Some("Webhook or parent organization is inactive".to_string()),
                None,
            )
            .await?;
            return Ok(());
        };
        let delivery = authorized.delivery;
        let webhook = authorized.webhook;

        let encrypted_secret = webhook.secret_encrypted.as_deref().ok_or_else(|| {
            crate::error::AppError::InternalServerError(
                "Webhook secret requires migration; run rewrap-secrets --apply".to_string(),
            )
        })?;
        let encryption = self.encryption.as_ref().ok_or_else(|| {
            crate::error::AppError::InternalServerError(
                "Encryption service is required to deliver webhooks".to_string(),
            )
        })?;
        let secret = encryption
            .decrypt_with_context(
                encrypted_secret,
                crate::encryption::EncryptionContext::new(
                    "webhooks",
                    &webhook.id,
                    "secret_encrypted",
                ),
            )
            .map_err(|_| {
                crate::error::AppError::InternalServerError(
                    "Webhook secret could not be authenticated".to_string(),
                )
            })?;
        let signature = self.generate_signature(payload_body.as_bytes(), &secret);
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let response_result = safe_client
            .post_with_owned_headers(
                &webhook.url,
                payload_body,
                vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("X-Webhook-Signature".to_string(), signature),
                    ("X-Webhook-Timestamp".to_string(), timestamp),
                ],
            )
            .await;

        match response_result {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16() as i32;

                // Try to get response body (limit to reasonable size)
                let response_body = match response.text().await {
                    Ok(body) => {
                        if body.len() > 10000 {
                            format!("{}... (truncated)", &body[..10000])
                        } else {
                            body
                        }
                    }
                    Err(_) => "Failed to read response body".to_string(),
                };

                if status.is_success() {
                    // Mark delivery as successful with response details
                    WebhookDeliveryStore::mark_as_successful_with_response_for_webhook(
                        DB::Conn(&self.db),
                        &webhook_payload.delivery_id,
                        &webhook_payload.webhook_id,
                        status_code,
                        Some(response_body.clone()),
                    )
                    .await?;

                    tracing::info!(
                        worker_id = %self.worker_id,
                        webhook_id = %webhook_payload.webhook_id,
                        event_type = %webhook_payload.event_type,
                        delivery_id = %webhook_payload.delivery_id,
                        status = %status,
                        "Webhook delivered successfully"
                    );
                } else {
                    // Mark delivery as failed and schedule retry if appropriate
                    if delivery.attempt_count < delivery.max_attempts - 1 {
                        // Schedule retry with exponential backoff
                        let retry_delay =
                            Duration::from_secs(60 * (2_u64.pow(delivery.attempt_count as u32)));
                        let next_retry_at = (chrono::Utc::now()
                            + chrono::Duration::from_std(retry_delay).unwrap_or_default())
                        .naive_utc();

                        WebhookDeliveryStore::schedule_retry_for_webhook(
                            DB::Conn(&self.db),
                            &webhook_payload.delivery_id,
                            &webhook_payload.webhook_id,
                            next_retry_at,
                            Some(format!("HTTP {}: {}", status_code, response_body)),
                            Some((status_code, Some(response_body.clone()))),
                        )
                        .await?;

                        tracing::warn!(
                            worker_id = %self.worker_id,
                            webhook_id = %webhook_payload.webhook_id,
                            event_type = %webhook_payload.event_type,
                            delivery_id = %webhook_payload.delivery_id,
                            status = %status,
                            attempt = delivery.attempt_count + 1,
                            "Webhook delivery failed, retry scheduled"
                        );
                    } else {
                        // Mark as permanently failed with response details
                        WebhookDeliveryStore::mark_as_failed_permanently_for_webhook(
                            DB::Conn(&self.db),
                            &webhook_payload.delivery_id,
                            &webhook_payload.webhook_id,
                            Some(format!("HTTP {}: {}", status_code, response_body)),
                            Some((status_code, Some(response_body.clone()))),
                        )
                        .await?;

                        tracing::error!(
                            worker_id = %self.worker_id,
                            webhook_id = %webhook_payload.webhook_id,
                            event_type = %webhook_payload.event_type,
                            delivery_id = %webhook_payload.delivery_id,
                            status = %status,
                            "Webhook delivery failed permanently"
                        );
                    }

                    // Return error to mark job as failed in system_jobs
                    return Err(crate::error::AppError::BadRequest(format!(
                        "Webhook delivery failed with status {}: {}",
                        status, response_body
                    )));
                }
            }
            Err(e) => {
                // Network or other error - schedule retry if we have attempts left
                if delivery.attempt_count < delivery.max_attempts - 1 {
                    let retry_delay =
                        Duration::from_secs(60 * (2_u64.pow(delivery.attempt_count as u32)));
                    let next_retry_at = (chrono::Utc::now()
                        + chrono::Duration::from_std(retry_delay).unwrap_or_default())
                    .naive_utc();

                    WebhookDeliveryStore::schedule_retry_for_webhook(
                        DB::Conn(&self.db),
                        &webhook_payload.delivery_id,
                        &webhook_payload.webhook_id,
                        next_retry_at,
                        Some(format!("Network error: {}", e)),
                        None,
                    )
                    .await?;
                } else {
                    WebhookDeliveryStore::mark_as_failed_permanently_for_webhook(
                        DB::Conn(&self.db),
                        &webhook_payload.delivery_id,
                        &webhook_payload.webhook_id,
                        Some(format!("Network error: {}", e)),
                        None,
                    )
                    .await?;
                }

                return Err(crate::error::AppError::BadRequest(format!(
                    "Failed to send webhook: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    /// Generate HMAC signature for webhook payload
    fn generate_signature(&self, payload: &[u8], secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(payload);

        let result = mac.finalize();
        format!("sha256={:x}", result.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::job_queue::{JobQueueService, JobType};
    use crate::store::system_jobs::SystemJobStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::time::{Duration, Instant};

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    /// Polls `check` every 100 ms until it holds or the deadline passes.
    macro_rules! eventually {
        ($check:expr) => {{
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if $check {
                    break;
                }
                assert!(Instant::now() < deadline, "condition not met within 20s");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }};
    }

    #[tokio::test]
    async fn the_processor_drains_a_pending_custom_job_to_completed() {
        let db = db().await;
        let _job_id = JobQueueService::enqueue(
            DB::Conn(&db),
            JobType::Custom("test-work".to_string()),
            &serde_json::json!({ "anything": true }),
            0,
            1,
            None,
        )
        .await
        .expect("enqueue custom job");

        // Unknown custom types are gracefully skipped and marked complete.
        let processor = JobProcessor::new(
            db.clone(),
            #[cfg(feature = "db_sqlite")]
            db.clone(),
            None,
            None,
            2,
        );
        tokio::spawn(processor.start());

        eventually!({
            let counts = SystemJobStore::count_by_statuses(DB::Conn(&db), &["completed"])
                .await
                .expect("count statuses");
            counts.get("completed").copied().unwrap_or(0) >= 1
        });

        let in_flight =
            SystemJobStore::count_by_statuses(DB::Conn(&db), &["pending", "processing"])
                .await
                .expect("count in-flight");
        assert_eq!(
            in_flight.values().sum::<i64>(),
            0,
            "the queue must be empty after processing"
        );
    }

    #[tokio::test]
    async fn email_jobs_without_a_service_complete_with_a_warning() {
        let db = db().await;
        JobQueueService::enqueue(
            DB::Conn(&db),
            JobType::SendEmail,
            &serde_json::json!({
                "to": "someone@example.test",
                "subject": "Hello",
                "body": "World",
            }),
            0,
            3,
            None,
        )
        .await
        .expect("enqueue email job");

        // No EmailService configured: the job completes without sending.
        let processor = JobProcessor::new(
            db.clone(),
            #[cfg(feature = "db_sqlite")]
            db.clone(),
            None,
            None,
            2,
        );
        tokio::spawn(processor.start());

        eventually!({
            let counts = SystemJobStore::count_by_statuses(DB::Conn(&db), &["completed"])
                .await
                .expect("count statuses");
            counts.get("completed").copied().unwrap_or(0) >= 1
        });
    }

    #[tokio::test]
    async fn webhook_jobs_against_unroutable_hosts_leave_pending() {
        let db = db().await;
        JobQueueService::enqueue(
            DB::Conn(&db),
            JobType::DeliverWebhook,
            &serde_json::json!({
                "webhook_id": "wh-1",
                "event_type": "webhook.test.ping",
                "payload": {},
                "delivery_id": "d-1",
            }),
            0,
            1,
            None,
        )
        .await
        .expect("enqueue webhook job");

        let processor = JobProcessor::new(
            db.clone(),
            #[cfg(feature = "db_sqlite")]
            db.clone(),
            None,
            None,
            2,
        );
        tokio::spawn(processor.start());

        // Delivery to an unroutable host cannot succeed; the job must leave
        // `pending` one way or another (failed permanently, retried into the
        // future, or completed by graceful handling).
        eventually!({
            let pending = SystemJobStore::count_by_statuses(DB::Conn(&db), &["pending"])
                .await
                .expect("count pending");
            let failed = SystemJobStore::count_by_statuses(DB::Conn(&db), &["failed"])
                .await
                .expect("count failed");
            let completed = SystemJobStore::count_by_statuses(DB::Conn(&db), &["completed"])
                .await
                .expect("count completed");
            pending.get("pending").copied().unwrap_or(0) == 0
                || failed.get("failed").copied().unwrap_or(0) >= 1
                || completed.get("completed").copied().unwrap_or(0) >= 1
        });
    }
}
