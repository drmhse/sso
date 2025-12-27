//! Job Queue Service - Persistent background job processing with Transactional Outbox pattern

use crate::error::{AppError, Result};
use crate::store::system_jobs::SystemJobStore;
use crate::store::webhook_deliveries::WebhookDeliveryStore;
use crate::store::DB;
use chrono::Utc;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json;

/// Job types that can be enqueued
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobType {
    SendEmail,
    DeliverWebhook,
    StreamAuditLogs,
    Custom(String),
}

impl JobType {
    pub fn as_str(&self) -> &str {
        match self {
            JobType::SendEmail => "send_email",
            JobType::DeliverWebhook => "deliver_webhook",
            JobType::StreamAuditLogs => "stream_audit_logs",
            JobType::Custom(s) => s,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "send_email" => JobType::SendEmail,
            "deliver_webhook" => JobType::DeliverWebhook,
            "stream_audit_logs" => JobType::StreamAuditLogs,
            _ => JobType::Custom(s.to_string()),
        }
    }
}

/// Email job payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailJobPayload {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub html: Option<String>,
}

/// Webhook job payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookJobPayload {
    pub webhook_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub delivery_id: String,
}

/// Audit log streaming job payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogStreamPayload {
    pub siem_config_id: String,
    pub audit_type: String, // "login_events", "mfa_audit_log", "organization_audit_log", "platform_audit_log"
    pub batch_id: String,
}

/// Job Queue Service
pub struct JobQueueService;

impl JobQueueService {
    /// Enqueue a job (can be called within a transaction)
    pub async fn enqueue<T: Serialize>(
        db: DB<'_>,
        job_type: JobType,
        payload: &T,
        priority: i32,
        max_retries: i32,
        scheduled_for: Option<chrono::DateTime<Utc>>,
    ) -> Result<String> {
        let payload_str = serde_json::to_string(payload)
            .map_err(|e| AppError::BadRequest(format!("Failed to serialize job payload: {}", e)))?;

        let job_id = SystemJobStore::create_job(
            db,
            job_type.as_str(),
            &payload_str,
            priority,
            max_retries,
            scheduled_for,
        )
        .await?;

        tracing::info!(
            job_id = %job_id,
            job_type = job_type.as_str(),
            "Job enqueued"
        );

        Ok(job_id)
    }

    /// Enqueue an email job
    pub async fn enqueue_email(
        db: DB<'_>,
        to: &str,
        subject: &str,
        body: &str,
        html: Option<String>,
    ) -> Result<String> {
        let payload = EmailJobPayload {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            html,
        };

        Self::enqueue(
            db,
            JobType::SendEmail,
            &payload,
            0,    // Normal priority
            3,    // Max 3 retries
            None, // Execute immediately
        )
        .await
    }

    /// Enqueue a webhook delivery job
    pub async fn enqueue_webhook(
        db: DB<'_>,
        webhook_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<String> {
        // Create a delivery record first
        let delivery_id = WebhookDeliveryStore::create_delivery(
            db.clone(),
            webhook_id,
            event_type,
            payload,
            5, // Max 5 attempts for webhooks
        )
        .await?;

        let job_payload = WebhookJobPayload {
            webhook_id: webhook_id.to_string(),
            event_type: event_type.to_string(),
            payload: payload.clone(),
            delivery_id,
        };

        Self::enqueue(
            db,
            JobType::DeliverWebhook,
            &job_payload,
            0,    // Normal priority
            5,    // Max 5 retries for webhooks
            None, // Execute immediately
        )
        .await
    }

    /// Enqueue an audit log streaming job
    pub async fn enqueue_audit_log_stream(
        db: DB<'_>,
        siem_config_id: &str,
        audit_type: &str,
        batch_id: &str,
    ) -> Result<String> {
        let job_payload = AuditLogStreamPayload {
            siem_config_id: siem_config_id.to_string(),
            audit_type: audit_type.to_string(),
            batch_id: batch_id.to_string(),
        };

        Self::enqueue(
            db,
            JobType::StreamAuditLogs,
            &job_payload,
            1,    // Higher priority for log streaming
            3,    // Max 3 retries
            None, // Execute immediately
        )
        .await
    }

    /// Get pending jobs for processing
    pub async fn get_pending_jobs(
        db: &DatabaseConnection,
        limit: u64,
    ) -> Result<Vec<crate::entities::system_jobs::Model>> {
        SystemJobStore::get_pending_jobs(DB::Conn(db), limit).await
    }

    /// Mark job as processing
    pub async fn mark_processing(db: &DatabaseConnection, job_id: &str) -> Result<()> {
        SystemJobStore::mark_as_processing(DB::Conn(db), job_id).await
    }

    /// Mark job as completed
    pub async fn mark_completed(db: &DatabaseConnection, job_id: &str) -> Result<()> {
        SystemJobStore::mark_as_completed(DB::Conn(db), job_id).await
    }

    /// Mark job as failed
    pub async fn mark_failed(
        db: &DatabaseConnection,
        job_id: &str,
        error_message: &str,
    ) -> Result<()> {
        SystemJobStore::mark_as_failed(DB::Conn(db), job_id, error_message).await
    }

    /// Mark job as permanently failed
    pub async fn mark_failed_permanently(
        db: &DatabaseConnection,
        job_id: &str,
        error_message: &str,
    ) -> Result<()> {
        SystemJobStore::mark_as_failed_permanently(DB::Conn(db), job_id, error_message).await
    }

    /// Cleanup old completed jobs
    pub async fn cleanup_old_jobs(db: &DatabaseConnection, days_to_keep: i64) -> Result<u64> {
        SystemJobStore::cleanup_old_jobs(DB::Conn(db), days_to_keep).await
    }
}
