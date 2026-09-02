use crate::db::models::DeviceCode;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::store::device_codes::DeviceCodeStore;
use chrono::{DateTime, Utc};
use rand::Rng;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

const USER_CODE_LENGTH: usize = 8;

pub struct DeviceFlowService;

impl DeviceFlowService {
    /// Generate a human-readable user code (e.g., "ABCD-EFGH")
    pub fn generate_user_code() -> String {
        let mut rng = rand::thread_rng();
        let chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // Exclude similar looking chars (0,O,1,I,L)
        let code: String = (0..USER_CODE_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..chars.len());
                chars.chars().nth(idx).unwrap()
            })
            .collect();

        // Format as XXXX-XXXX
        format!("{}-{}", &code[..4], &code[4..])
    }

    #[allow(dead_code)]
    pub fn generate_device_code() -> String {
        Uuid::new_v4().to_string()
    }

    /// Find a device code by user code
    pub async fn find_by_user_code(
        db: &DatabaseConnection,
        user_code: &str,
    ) -> Result<Option<DeviceCode>> {
        let entity = DeviceCodeStore::find_by_user_code(DB::Conn(db), user_code).await?;

        Ok(entity.map(|e| DeviceCode {
            id: e.id,
            device_code: e.device_code,
            user_code: e.user_code,
            client_id: e.client_id,
            org_slug: e.org_slug,
            service_slug: e.service_slug,
            expires_at: DateTime::from_naive_utc_and_offset(e.expires_at, Utc),
            user_id: e.user_id,
            status: e.status,
        }))
    }

    /// Find a device code by device code
    pub async fn find_by_device_code(
        db: &DatabaseConnection,
        device_code: &str,
    ) -> Result<Option<DeviceCode>> {
        let entity = DeviceCodeStore::find_by_device_code(DB::Conn(db), device_code).await?;

        Ok(entity.map(|e| DeviceCode {
            id: e.id,
            device_code: e.device_code,
            user_code: e.user_code,
            client_id: e.client_id,
            org_slug: e.org_slug,
            service_slug: e.service_slug,
            expires_at: DateTime::from_naive_utc_and_offset(e.expires_at, Utc),
            user_id: e.user_id,
            status: e.status,
        }))
    }

    /// Check if a device code is expired
    pub fn is_expired(device_code: &DeviceCode) -> bool {
        device_code.expires_at < Utc::now()
    }

    /// Check if a device code is authorized
    pub fn is_authorized(device_code: &DeviceCode) -> bool {
        device_code.status == "authorized" && device_code.user_id.is_some()
    }

    /// Validate device code for token exchange
    pub async fn validate_for_token_exchange(
        db: &DatabaseConnection,
        device_code: &str,
        client_id: &str,
    ) -> Result<DeviceCode> {
        let device_code_record = Self::find_by_device_code(db, device_code)
            .await?
            .ok_or_else(|| AppError::BadRequest("Invalid device code".to_string()))?;

        // Validate client_id matches
        if device_code_record.client_id != client_id {
            return Err(AppError::Unauthorized("Invalid client".to_string()));
        }

        // Check if expired
        if Self::is_expired(&device_code_record) {
            return Err(AppError::DeviceCodeExpired);
        }

        // Check if authorized
        if !Self::is_authorized(&device_code_record) {
            return Err(AppError::DeviceCodePending);
        }

        Ok(device_code_record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_user_code_generation() {
        let code = DeviceFlowService::generate_user_code();
        assert_eq!(code.len(), 9); // 8 chars + 1 dash
        assert!(code.contains('-'));
        assert_eq!(code.chars().filter(|c| *c == '-').count(), 1);
    }

    #[test]
    fn test_device_code_generation() {
        let code = DeviceFlowService::generate_device_code();
        assert!(!code.is_empty());
        // Should be a valid UUID format
        assert!(Uuid::parse_str(&code).is_ok());
    }

    #[test]
    fn test_is_expired() {
        let expired_code = DeviceCode {
            id: "test".to_string(),
            device_code: "test".to_string(),
            user_code: "test".to_string(),
            client_id: "test".to_string(),
            org_slug: "test".to_string(),
            service_slug: "test".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
            user_id: None,
            status: "pending".to_string(),
        };

        assert!(DeviceFlowService::is_expired(&expired_code));
    }

    #[test]
    fn test_is_authorized() {
        let authorized_code = DeviceCode {
            id: "test".to_string(),
            device_code: "test".to_string(),
            user_code: "test".to_string(),
            client_id: "test".to_string(),
            org_slug: "test".to_string(),
            service_slug: "test".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            user_id: Some("user_123".to_string()),
            status: "authorized".to_string(),
        };

        assert!(DeviceFlowService::is_authorized(&authorized_code));
    }
}
