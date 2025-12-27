//! Audit Log Streaming Service
//!
//! This service handles streaming audit logs to external SIEM systems like Datadog and Splunk.
//! It uses the SQL Job Queue for reliable delivery and supports multiple providers.

use crate::error::{AppError, Result};
use crate::services::job_queue::{JobQueueService, AuditLogStreamPayload};
use crate::store::siem_configs::SiemConfigStore;
use crate::store::{DB};
use reqwest::Client;
use sea_orm::{DatabaseConnection, EntityTrait, QuerySelect, QueryOrder};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

/// Supported SIEM providers
#[derive(Debug, Clone, strum::Display)]
pub enum SiemProvider {
    #[strum(serialize = "datadog")]
    Datadog,
    #[strum(serialize = "splunk")]
    Splunk,
    #[strum(serialize = "elastic")]
    Elastic,
    #[strum(serialize = "custom")]
    Custom,
}

impl SiemProvider {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "datadog" => SiemProvider::Datadog,
            "splunk" => SiemProvider::Splunk,
            "elastic" => SiemProvider::Elastic,
            _ => SiemProvider::Custom,
        }
    }
}

/// Audit log streaming service
pub struct AuditLogStreamingService {
    http_client: Client,
}

impl AuditLogStreamingService {
    pub fn new() -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { http_client }
    }

    /// Trigger streaming for all enabled SIEM configurations
    pub async fn trigger_streaming_for_all(
        &self,
        db: &DatabaseConnection,
    ) -> Result<Vec<String>> {
        let configs = SiemConfigStore::get_enabled_configs(db).await?;
        let mut job_ids = Vec::new();

        for config in configs {
            // Queue jobs for each audit log type
            let audit_types = vec![
                "login_events",
                "mfa_audit_log",
                "organization_audit_log",
                "platform_audit_log",
            ];

            for audit_type in audit_types {
                let batch_id = Uuid::new_v4().to_string();
                let job_id = JobQueueService::enqueue_audit_log_stream(
                    DB::Conn(db),
                    &config.id,
                    audit_type,
                    &batch_id,
                )
                .await?;

                job_ids.push(job_id);
            }
        }

        tracing::info!(
            jobs_created = job_ids.len(),
            "Audit log streaming jobs created"
        );

        Ok(job_ids)
    }

    /// Process a single audit log streaming job
    pub async fn process_streaming_job(
        &self,
        db: &DatabaseConnection,
        payload: AuditLogStreamPayload,
    ) -> Result<()> {
        // Get SIEM configuration
        let config = SiemConfigStore::get_by_id(DB::Conn(db), &payload.siem_config_id)
            .await?
            .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

        if !config.enabled {
            tracing::warn!(
                siem_config_id = %payload.siem_config_id,
                "SIEM configuration is disabled, skipping job"
            );
            return Ok(());
        }

        // Parse batch size
        let batch_size: i64 = config.batch_size.parse()
            .map_err(|e| AppError::BadRequest(format!("Invalid batch_size: {}", e)))?;

        // Get audit logs based on type, using cursor for reliability
        let audit_logs = match payload.audit_type.as_str() {
            "login_events" => self.get_login_events(db, batch_size, &config.last_processed_log_id).await?,
            "mfa_audit_log" => self.get_mfa_audit_logs(db, batch_size, &config.last_processed_log_id).await?,
            "organization_audit_log" => self.get_organization_audit_logs(db, batch_size, &config.last_processed_log_id).await?,
            "platform_audit_log" => self.get_platform_audit_logs(db, batch_size, &config.last_processed_log_id).await?,
            _ => return Err(AppError::BadRequest(format!("Unsupported audit type: {}", payload.audit_type))),
        };

        if audit_logs.is_empty() {
            tracing::debug!(
                audit_type = %payload.audit_type,
                "No audit logs to stream"
            );
            return Ok(());
        }

        // Transform and send to SIEM
        let provider = SiemProvider::from_str(&config.provider);
        let payload_data = self.transform_for_provider(provider.clone(), &payload.audit_type, audit_logs.clone())?;
        let logs_count = payload_data.len();

        self.send_to_siem(provider, &config.endpoint_url, &config.api_key, &config.auth_header, payload_data)
            .await?;

        // Extract the last log ID from this batch for cursor tracking
        let last_log_id = if logs_count > 0 {
            audit_logs.last().and_then(|log| log.get("id").and_then(|id| id.as_str())).map(|s| s.to_string())
        } else {
            None
        };

        // Update last successful batch timestamp and cursor
        SiemConfigStore::update_last_successful_batch(DB::Conn(db), &payload.siem_config_id, last_log_id)
            .await?;

        tracing::info!(
            siem_config_id = %payload.siem_config_id,
            audit_type = %payload.audit_type,
            batch_id = %payload.batch_id,
            logs_count = logs_count,
            "Audit log batch streamed successfully"
        );

        Ok(())
    }

    /// Get login events for streaming using cursor-based pagination
    async fn get_login_events(&self, db: &DatabaseConnection, limit: i64, last_processed_log_id: &Option<String>) -> Result<Vec<serde_json::Value>> {
        use crate::entities::prelude::LoginEvents;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

        let events = if let Some(last_id) = last_processed_log_id {
            // Cursor-based query: get logs with ID > last_processed_log_id, ordered by ID then created_at
            LoginEvents::find()
                .filter(crate::entities::login_events::Column::Id.gt(last_id))
                .order_by_asc(crate::entities::login_events::Column::Id)
                .then_order_by_asc(crate::entities::login_events::Column::CreatedAt)
                .limit(limit as u64)
                .all(db)
                .await?
        } else {
            // First time or reset: get the most recent logs ordered by ID descending for initial sync
            LoginEvents::find()
                .order_by_desc(crate::entities::login_events::Column::Id)
                .limit(limit as u64)
                .all(db)
                .await?
        };

        let mut result = Vec::new();
        for event in events {
            result.push(json!({
                "id": event.id,
                "user_id": event.user_id,
                "service_id": event.service_id,
                "provider": event.provider,
                "ip_address": event.ip_address,
                "user_agent": event.user_agent,
                "created_at": event.created_at,
                "risk_score": event.risk_score,
                "risk_factors": event.risk_factors,
                "geo_country": event.geo_country,
                "geo_city": event.geo_city,
                "geo_lat": event.geo_lat,
                "geo_long": event.geo_long,
                "event_type": "authentication",
                "category": "security"
            }));
        }

        Ok(result)
    }

    /// Get MFA audit logs for streaming using cursor-based pagination
    async fn get_mfa_audit_logs(&self, db: &DatabaseConnection, limit: i64, last_processed_log_id: &Option<String>) -> Result<Vec<serde_json::Value>> {
        use crate::entities::prelude::MfaAuditLog;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

        let logs = if let Some(last_id) = last_processed_log_id {
            // Cursor-based query: get logs with ID > last_processed_log_id
            MfaAuditLog::find()
                .filter(crate::entities::mfa_audit_log::Column::Id.gt(last_id))
                .order_by_asc(crate::entities::mfa_audit_log::Column::Id)
                .then_order_by_asc(crate::entities::mfa_audit_log::Column::CreatedAt)
                .limit(limit as u64)
                .all(db)
                .await?
        } else {
            // First time or reset: get the most recent logs
            MfaAuditLog::find()
                .order_by_desc(crate::entities::mfa_audit_log::Column::Id)
                .limit(limit as u64)
                .all(db)
                .await?
        };

        let mut result = Vec::new();
        for log in logs {
            result.push(json!({
                "id": log.id,
                "user_id": log.user_id,
                "event_type": log.event_type,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "success": log.success,
                "details": log.details,
                "created_at": log.created_at,
                "category": "mfa",
                "event_category": "security"
            }));
        }

        Ok(result)
    }

    /// Get organization audit logs for streaming using cursor-based pagination
    async fn get_organization_audit_logs(&self, db: &DatabaseConnection, limit: i64, last_processed_log_id: &Option<String>) -> Result<Vec<serde_json::Value>> {
        use crate::entities::prelude::OrganizationAuditLog;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

        let logs = if let Some(last_id) = last_processed_log_id {
            // Cursor-based query: get logs with ID > last_processed_log_id
            OrganizationAuditLog::find()
                .filter(crate::entities::organization_audit_log::Column::Id.gt(last_id))
                .order_by_asc(crate::entities::organization_audit_log::Column::Id)
                .then_order_by_asc(crate::entities::organization_audit_log::Column::CreatedAt)
                .limit(limit as u64)
                .all(db)
                .await?
        } else {
            // First time or reset: get the most recent logs
            OrganizationAuditLog::find()
                .order_by_desc(crate::entities::organization_audit_log::Column::Id)
                .limit(limit as u64)
                .all(db)
                .await?
        };

        let mut result = Vec::new();
        for log in logs {
            result.push(json!({
                "id": log.id,
                "org_id": log.org_id,
                "actor_user_id": log.actor_user_id,
                "action": log.action,
                "target_type": log.target_type,
                "target_id": log.target_id,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "success": log.success,
                "details": log.details,
                "created_at": log.created_at,
                "category": "governance",
                "event_category": "admin"
            }));
        }

        Ok(result)
    }

    /// Get platform audit logs for streaming using cursor-based pagination
    async fn get_platform_audit_logs(&self, db: &DatabaseConnection, limit: i64, last_processed_log_id: &Option<String>) -> Result<Vec<serde_json::Value>> {
        use crate::entities::prelude::PlatformAuditLog;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

        let logs = if let Some(last_id) = last_processed_log_id {
            // Cursor-based query: get logs with ID > last_processed_log_id
            PlatformAuditLog::find()
                .filter(crate::entities::platform_audit_log::Column::Id.gt(last_id))
                .order_by_asc(crate::entities::platform_audit_log::Column::Id)
                .then_order_by_asc(crate::entities::platform_audit_log::Column::CreatedAt)
                .limit(limit as u64)
                .all(db)
                .await?
        } else {
            // First time or reset: get the most recent logs
            PlatformAuditLog::find()
                .order_by_desc(crate::entities::platform_audit_log::Column::Id)
                .limit(limit as u64)
                .all(db)
                .await?
        };

        let mut result = Vec::new();
        for log in logs {
            result.push(json!({
                "id": log.id,
                "platform_owner_id": log.platform_owner_id,
                "action": log.action,
                "target_type": log.target_type,
                "target_id": log.target_id,
                "metadata": log.metadata,
                "created_at": log.created_at,
                "category": "platform",
                "event_category": "admin"
            }));
        }

        Ok(result)
    }

    /// Transform audit logs for specific SIEM provider format
    fn transform_for_provider(
        &self,
        provider: SiemProvider,
        audit_type: &str,
        mut logs: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>> {
        match provider {
            SiemProvider::Datadog => {
                // Datadog expects logs with specific fields
                for log in &mut logs {
                    log["ddsource"] = json!("sso-platform");
                    log["ddtags"] = json!(format!("audit_type:{}", audit_type));
                    log["hostname"] = json!("sso-api");
                    log["service"] = json!("identity-provider");
                }
            }
            SiemProvider::Splunk => {
                // Splunk HEC format
                for log in &mut logs {
                    log["time"] = log["created_at"].clone();
                    log["index"] = json!("sso_audit");
                    log["source"] = json!("sso-platform");
                    log["sourcetype"] = json!("json");
                }
            }
            SiemProvider::Elastic => {
                // Elasticsearch format
                for log in &mut logs {
                    log["@timestamp"] = log["created_at"].clone();
                    log["index_name"] = json!("sso-audit-logs");
                }
            }
            SiemProvider::Custom => {
                // Keep original format for custom providers
            }
        }

        Ok(logs)
    }

    /// Send audit logs to SIEM endpoint
    async fn send_to_siem(
        &self,
        provider: SiemProvider,
        endpoint_url: &str,
        api_key: &Option<String>,
        auth_header: &Option<String>,
        logs: Vec<serde_json::Value>,
    ) -> Result<()> {
        let mut request = self.http_client.post(endpoint_url);

        // Add authentication headers
        match provider {
            SiemProvider::Datadog => {
                if let Some(key) = api_key {
                    request = request.header("DD-API-KEY", key);
                }
            }
            SiemProvider::Splunk => {
                if let Some(key) = api_key {
                    request = request.header("Authorization", format!("Splunk {}", key));
                }
                request = request.header("Content-Type", "application/json");
            }
            SiemProvider::Elastic => {
                if let Some(key) = api_key {
                    request = request.header("Authorization", format!("ApiKey {}", key));
                }
            }
            SiemProvider::Custom => {
                if let Some(header) = auth_header {
                    // Parse custom auth header (e.g., "Bearer token123" or "X-API-Key: key123")
                    if let Some((name, value)) = header.split_once(':') {
                        request = request.header(name.trim(), value.trim());
                    } else {
                        request = request.header("Authorization", header);
                    }
                }
            }
        }

        // Prepare payload based on provider
        let payload = match provider {
            SiemProvider::Datadog => json!({ "logs": logs }),
            SiemProvider::Splunk => json!({
                "events": logs,
                "index": "sso_audit",
                "source": "sso-platform",
                "sourcetype": "json"
            }),
            SiemProvider::Elastic => json!({ "docs": logs }),
            SiemProvider::Custom => json!(logs),
        };

        let response = request
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("Failed to send logs to SIEM: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::InternalServerError(format!(
                "SIEM returned error status {}: {}",
                status, body
            )));
        }

        tracing::debug!(
            provider = %provider,
            endpoint_url = %endpoint_url,
            logs_count = logs.len(),
            "Audit logs sent to SIEM successfully"
        );

        Ok(())
    }
}

impl Default for AuditLogStreamingService {
    fn default() -> Self {
        Self::new()
    }
}