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
use crate::store::webhooks::WebhookStore;
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
    max_concurrent_jobs: usize,
}

impl JobProcessor {
    pub fn new(
        db: DatabaseConnection,
        #[cfg(feature = "db_sqlite")] db_writer: DatabaseConnection,
        email_service: Option<Arc<EmailService>>,
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
            max_concurrent_jobs,
        }
    }

    /// Start the job processor worker with concurrent job processing
    ///
    /// Uses a concurrent claim-and-process pattern:
    /// 1. Continuously claim jobs up to max_concurrent_jobs limit
    /// 2. Each claimed job is processed in its own async task
    /// 3. When a slot frees up, immediately try to claim another job
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

        // Get the webhook configuration
        let webhook = WebhookStore::find_by_id(DB::Conn(&self.db), &webhook_payload.webhook_id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Webhook not found".to_string()))?;

        if !webhook.is_active {
            tracing::warn!(
                worker_id = %self.worker_id,
                webhook_id = %webhook_payload.webhook_id,
                "Webhook is inactive, skipping"
            );
            // Mark delivery as permanently failed since webhook is inactive
            WebhookDeliveryStore::mark_as_failed_permanently(
                DB::Conn(&self.db),
                &webhook_payload.delivery_id,
                Some("Webhook is inactive".to_string()),
            )
            .await?;
            return Ok(());
        }

        let payload_body = serde_json::to_string(&webhook_payload.payload).map_err(|e| {
            crate::error::AppError::InternalServerError(format!(
                "Failed to serialize webhook payload: {}",
                e
            ))
        })?;
        let signature = self.generate_signature(payload_body.as_bytes(), &webhook.secret);
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let safe_client = SafeHttpClient::new()?;

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
                    WebhookDeliveryStore::mark_as_successful_with_response(
                        DB::Conn(&self.db),
                        &webhook_payload.delivery_id,
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
                    let delivery =
                        WebhookDeliveryStore::get_pending_deliveries(DB::Conn(&self.db), 1).await?;
                    if let Some(current_delivery) = delivery.first() {
                        if current_delivery.id == webhook_payload.delivery_id
                            && current_delivery.attempt_count < current_delivery.max_attempts - 1
                        {
                            // Schedule retry with exponential backoff
                            let retry_delay = Duration::from_secs(
                                60 * (2_u64.pow(current_delivery.attempt_count as u32)),
                            );
                            let next_retry_at = (chrono::Utc::now()
                                + chrono::Duration::from_std(retry_delay).unwrap_or_default())
                            .naive_utc();

                            WebhookDeliveryStore::schedule_retry_with_response(
                                DB::Conn(&self.db),
                                &webhook_payload.delivery_id,
                                next_retry_at,
                                Some(format!("HTTP {}: {}", status_code, response_body)),
                                status_code,
                                Some(response_body.clone()),
                            )
                            .await?;

                            tracing::warn!(
                                worker_id = %self.worker_id,
                                webhook_id = %webhook_payload.webhook_id,
                                event_type = %webhook_payload.event_type,
                                delivery_id = %webhook_payload.delivery_id,
                                status = %status,
                                attempt = current_delivery.attempt_count + 1,
                                "Webhook delivery failed, retry scheduled"
                            );
                        } else {
                            // Mark as permanently failed with response details
                            WebhookDeliveryStore::mark_as_failed_permanently_with_response(
                                DB::Conn(&self.db),
                                &webhook_payload.delivery_id,
                                Some(format!("HTTP {}: {}", status_code, response_body)),
                                status_code,
                                Some(response_body.clone()),
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
                let delivery =
                    WebhookDeliveryStore::get_pending_deliveries(DB::Conn(&self.db), 1).await?;
                if let Some(current_delivery) = delivery.first() {
                    if current_delivery.id == webhook_payload.delivery_id
                        && current_delivery.attempt_count < current_delivery.max_attempts - 1
                    {
                        let retry_delay = Duration::from_secs(
                            60 * (2_u64.pow(current_delivery.attempt_count as u32)),
                        );
                        let next_retry_at = (chrono::Utc::now()
                            + chrono::Duration::from_std(retry_delay).unwrap_or_default())
                        .naive_utc();

                        WebhookDeliveryStore::schedule_retry(
                            DB::Conn(&self.db),
                            &webhook_payload.delivery_id,
                            next_retry_at,
                            Some(format!("Network error: {}", e)),
                        )
                        .await?;
                    } else {
                        WebhookDeliveryStore::mark_as_failed_permanently(
                            DB::Conn(&self.db),
                            &webhook_payload.delivery_id,
                            Some(format!("Network error: {}", e)),
                        )
                        .await?;
                    }
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
