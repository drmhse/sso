//! Log Streamer Service
//!
//! Handles secure log streaming to external SIEM systems (HTTP, S3, Datadog) with encryption.

use crate::encryption::EncryptionService;
use crate::entities::log_streams;
use crate::error::{AppError, Result};
use crate::services::job_queue::{JobQueueService, JobType};
use crate::store::log_streams::LogStreamStore;
use crate::store::DB;
use aws_sdk_s3::{primitives::ByteStream, Client as S3Client};
use chrono::Utc;
use reqwest::Client;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

/// Log stream configuration types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogStreamConfig {
    Http {
        endpoint_url: String,
        api_key: Option<String>,
        auth_header: Option<String>,
        batch_size: u32,
    },
    S3 {
        bucket: String,
        region: String,
        access_key_id: String,
        secret_access_key: String,
        prefix: Option<String>,
    },
    Datadog {
        api_key: String,
        site: String,
        service: Option<String>,
        hostname: Option<String>,
    },
}

/// Log stream type identifiers
#[derive(Debug, Clone, strum::Display)]
pub enum LogStreamType {
    #[strum(serialize = "http")]
    Http,
    #[strum(serialize = "s3")]
    S3,
    #[strum(serialize = "datadog")]
    Datadog,
}

/// Log streamer service
pub struct LogStreamerService {
    http_client: Client,
    encryption_service: EncryptionService,
}

impl LogStreamerService {
    pub fn new(encryption_service: EncryptionService) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http_client,
            encryption_service,
        }
    }

    /// Create a new log stream for an organization
    pub async fn create_stream(
        &self,
        db: DB<'_>,
        org_id: &str,
        name: &str,
        stream_type: LogStreamType,
        config: LogStreamConfig,
    ) -> Result<String> {
        // Serialize and encrypt the configuration
        let config_json = serde_json::to_string(&config)
            .map_err(|e| AppError::BadRequest(format!("Failed to serialize config: {}", e)))?;

        let config_encrypted = self.encryption_service.encrypt(&config_json).map_err(|e| {
            AppError::InternalServerError(format!("Failed to encrypt config: {}", e))
        })?;

        let stream_id =
            LogStreamStore::create(db, org_id, name, &stream_type.to_string(), config_encrypted)
                .await?;

        tracing::info!(
            stream_id = %stream_id,
            org_id = %org_id,
            name = %name,
            stream_type = %stream_type,
            "Log stream created"
        );

        Ok(stream_id)
    }

    /// Get log stream configuration (decrypted)
    pub async fn get_stream_config(
        &self,
        db: &DatabaseConnection,
        stream_id: &str,
    ) -> Result<(log_streams::Model, LogStreamConfig)> {
        let stream = LogStreamStore::get_by_id(DB::Conn(db), stream_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Log stream not found".to_string()))?;

        // Decrypt the configuration
        let config_json_str = self
            .encryption_service
            .decrypt(&stream.config_encrypted)
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to decrypt config: {}", e))
            })?;

        let config: LogStreamConfig = serde_json::from_str(&config_json_str)
            .map_err(|e| AppError::InternalServerError(format!("Failed to parse config: {}", e)))?;

        Ok((stream, config))
    }

    /// Queue log entry for streaming to all active streams for an organization
    pub async fn stream_log_entry(
        &self,
        db: &DatabaseConnection,
        org_id: &str,
        log_entry: serde_json::Value,
        audit_type: &str,
    ) -> Result<()> {
        // Find active streams for the organization
        let streams = LogStreamStore::find_active_by_org(db, org_id).await?;

        if streams.is_empty() {
            tracing::debug!(
                org_id = %org_id,
                "No active log streams for organization"
            );
            return Ok(());
        }

        // Create job payload with log entry and stream IDs
        let job_payload = json!({
            "org_id": org_id,
            "audit_type": audit_type,
            "log_entry": log_entry,
            "stream_ids": streams.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            "timestamp": Utc::now().to_rfc3339()
        });

        // Enqueue the job
        JobQueueService::enqueue(
            DB::Conn(db),
            JobType::StreamAuditLogs,
            &job_payload,
            1,    // Higher priority for log streaming
            3,    // Max 3 retries
            None, // Execute immediately
        )
        .await?;

        tracing::info!(
            org_id = %org_id,
            stream_count = streams.len(),
            audit_type = %audit_type,
            "Log streaming job queued"
        );

        Ok(())
    }
}

/// Background job worker for log delivery
#[derive(Clone)]
pub struct LogDeliveryWorker {
    http_client: Client,
    encryption_service: EncryptionService,
}

impl LogDeliveryWorker {
    pub fn new(encryption_service: EncryptionService) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(60)) // Longer timeout for S3 uploads
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http_client,
            encryption_service,
        }
    }

    /// Process a log delivery job
    pub async fn process_job(
        &self,
        db: &DatabaseConnection,
        job_payload: &serde_json::Value,
    ) -> Result<()> {
        let org_id = job_payload["org_id"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest("Missing org_id in job payload".to_string()))?;

        let audit_type = job_payload["audit_type"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest("Missing audit_type in job payload".to_string()))?;

        let log_entry = &job_payload["log_entry"];
        let stream_ids: Vec<String> = job_payload["stream_ids"]
            .as_array()
            .ok_or_else(|| AppError::BadRequest("Invalid stream_ids format".to_string()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        tracing::info!(
            org_id = %org_id,
            audit_type = %audit_type,
            stream_count = stream_ids.len(),
            "Processing log delivery job"
        );

        // Process each stream
        let mut successes = 0;
        let mut failures = 0;

        for stream_id in stream_ids {
            match self
                .deliver_to_stream(db, &stream_id, log_entry, audit_type)
                .await
            {
                Ok(()) => {
                    successes += 1;
                    tracing::debug!(stream_id = %stream_id, "Log delivered successfully");
                }
                Err(e) => {
                    failures += 1;
                    tracing::error!(
                        stream_id = %stream_id,
                        error = %e,
                        "Failed to deliver log to stream"
                    );
                }
            }
        }

        tracing::info!(
            org_id = %org_id,
            successes = successes,
            failures = failures,
            "Log delivery job completed"
        );

        Ok(())
    }

    /// Deliver log entry to a specific stream
    async fn deliver_to_stream(
        &self,
        db: &DatabaseConnection,
        stream_id: &str,
        log_entry: &serde_json::Value,
        audit_type: &str,
    ) -> Result<()> {
        // Get and decrypt stream configuration
        let (stream, config) = {
            let service = LogStreamerService::new(self.encryption_service.clone());
            service.get_stream_config(db, stream_id).await?
        };

        let result = match &stream.stream_type.as_str() {
            &"http" => {
                if let LogStreamConfig::Http {
                    endpoint_url,
                    api_key,
                    auth_header,
                    ..
                } = &config
                {
                    self.deliver_to_http(endpoint_url, api_key, auth_header, log_entry)
                        .await
                } else {
                    Err(AppError::InternalServerError(
                        "Invalid HTTP config".to_string(),
                    ))
                }
            }
            &"s3" => {
                if let LogStreamConfig::S3 {
                    bucket,
                    region,
                    access_key_id,
                    secret_access_key,
                    prefix,
                } = &config
                {
                    self.deliver_to_s3(
                        bucket,
                        region,
                        access_key_id,
                        secret_access_key,
                        prefix,
                        &stream.org_id.clone(),
                        audit_type,
                        log_entry,
                    )
                    .await
                } else {
                    Err(AppError::InternalServerError(
                        "Invalid S3 config".to_string(),
                    ))
                }
            }
            &"datadog" => {
                if let LogStreamConfig::Datadog {
                    api_key,
                    site,
                    service,
                    hostname,
                } = &config
                {
                    self.deliver_to_datadog(api_key, site, service, hostname, log_entry)
                        .await
                } else {
                    Err(AppError::InternalServerError(
                        "Invalid Datadog config".to_string(),
                    ))
                }
            }
            _ => Err(AppError::InternalServerError(format!(
                "Unsupported stream type: {}",
                stream.stream_type
            ))),
        };

        // Update stream delivery status
        let success = result.is_ok();
        LogStreamStore::update_delivery_status(DB::Conn(db), stream_id, success).await?;

        result
    }

    /// Deliver log to HTTP endpoint
    async fn deliver_to_http(
        &self,
        endpoint_url: &str,
        api_key: &Option<String>,
        auth_header: &Option<String>,
        log_entry: &serde_json::Value,
    ) -> Result<()> {
        let mut request = self.http_client.post(endpoint_url).json(log_entry);

        // Add authentication
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }
        if let Some(header) = auth_header {
            if let Some((name, value)) = header.split_once(':') {
                request = request.header(name.trim(), value.trim());
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::InternalServerError(format!(
                "HTTP delivery failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Deliver log to Datadog
    async fn deliver_to_datadog(
        &self,
        api_key: &str,
        site: &str,
        service: &Option<String>,
        hostname: &Option<String>,
        log_entry: &serde_json::Value,
    ) -> Result<()> {
        let mut log_entry = log_entry.clone();

        // Add Datadog specific fields
        log_entry["ddsource"] = json!("sso-platform");
        log_entry["ddtags"] = json!(format!(
            "source:sso,service:{}",
            service.as_deref().unwrap_or("identity-provider")
        ));
        log_entry["hostname"] = json!(hostname.as_deref().unwrap_or("sso-api"));

        let payload = json!({ "logs": [log_entry] });

        let response = self
            .http_client
            .post(&format!("https://http-intake.logs.{}/v1/input", site))
            .header("Content-Type", "application/json")
            .header("DD-API-KEY", api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("Datadog request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::InternalServerError(format!(
                "Datadog delivery failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Deliver log to S3
    async fn deliver_to_s3(
        &self,
        bucket: &str,
        region: &str,
        access_key_id: &str,
        secret_access_key: &str,
        prefix: &Option<String>,
        org_id: &str,
        _audit_type: &str,
        log_entry: &serde_json::Value,
    ) -> Result<()> {
        let config = aws_sdk_s3::config::Builder::new()
            .region(aws_sdk_s3::config::Region::new(region.to_string()))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                access_key_id,
                secret_access_key,
                None,
                None,
                "sso-log-streamer",
            ))
            .build();

        let client = S3Client::from_conf(config);

        let now = Utc::now();
        let key = format!(
            "{}sso-logs/{}/{}/{:02}/{:02}/{}.json",
            prefix.as_deref().unwrap_or_default(),
            org_id,
            now.format("%Y"),
            now.format("%m"),
            now.format("%d"),
            Uuid::new_v4()
        );

        let body = serde_json::to_vec(log_entry).map_err(|e| {
            AppError::InternalServerError(format!("Failed to serialize log: {}", e))
        })?;

        client
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(ByteStream::from(body))
            .content_type("application/json")
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("S3 upload failed: {}", e)))?;

        Ok(())
    }
}

impl Default for LogStreamerService {
    fn default() -> Self {
        Self::new(
            crate::encryption::EncryptionService::new()
                .expect("Failed to create encryption service"),
        )
    }
}

impl Default for LogDeliveryWorker {
    fn default() -> Self {
        Self::new(
            crate::encryption::EncryptionService::new()
                .expect("Failed to create encryption service"),
        )
    }
}
