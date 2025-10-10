use crate::constants::DEVICE_CODE_EXPIRE_MINUTES;
use crate::db::models::DeviceCode;
use crate::error::{AppError, Result};
use chrono::{Duration, Utc};
use rand::Rng;
use sqlx::SqlitePool;
use uuid::Uuid;

const USER_CODE_LENGTH: usize = 8;

pub struct DeviceFlowService;

impl DeviceFlowService {
    /// Generate a human-readable user code (e.g., "ABCD-EFGH")
    pub fn generate_user_code() -> String {
        let mut rng = rand::thread_rng();
        let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Exclude similar looking chars
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

    #[allow(dead_code)]
    pub async fn create_device_code(
        pool: &SqlitePool,
        client_id: &str,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<DeviceCode> {
        let id = Uuid::new_v4().to_string();
        let device_code_str = Self::generate_device_code();
        let user_code = Self::generate_user_code();
        let expires_at = Utc::now() + Duration::minutes(DEVICE_CODE_EXPIRE_MINUTES);

        // Use INSERT ... RETURNING for efficiency
        let device_code = sqlx::query_as::<_, DeviceCode>(
            r#"
            INSERT INTO device_codes (id, device_code, user_code, client_id, org_slug, service_slug, expires_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&device_code_str)
        .bind(&user_code)
        .bind(client_id)
        .bind(org_slug)
        .bind(service_slug)
        .bind(expires_at)
        .fetch_one(pool)
        .await?;

        Ok(device_code)
    }

    /// Find a device code by user code
    pub async fn find_by_user_code(
        pool: &SqlitePool,
        user_code: &str,
    ) -> Result<Option<DeviceCode>> {
        let device_code = sqlx::query_as::<_, DeviceCode>(
            r#"
            SELECT * FROM device_codes WHERE user_code = ?
            "#,
        )
        .bind(user_code)
        .fetch_optional(pool)
        .await?;

        Ok(device_code)
    }

    /// Find a device code by device code
    pub async fn find_by_device_code(
        pool: &SqlitePool,
        device_code: &str,
    ) -> Result<Option<DeviceCode>> {
        let device_code_record = sqlx::query_as::<_, DeviceCode>(
            r#"
            SELECT * FROM device_codes WHERE device_code = ?
            "#,
        )
        .bind(device_code)
        .fetch_optional(pool)
        .await?;

        Ok(device_code_record)
    }

    #[allow(dead_code)]
    pub async fn authorize(
        pool: &SqlitePool,
        user_code: &str,
        user_id: &str,
    ) -> Result<DeviceCode> {
        // Use UPDATE ... RETURNING to avoid a second query
        let device_code = sqlx::query_as::<_, DeviceCode>(
            r#"
            UPDATE device_codes
            SET user_id = ?, status = 'authorized'
            WHERE user_code = ?
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(user_code)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid user code".to_string()))?;

        Ok(device_code)
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
        pool: &SqlitePool,
        device_code: &str,
        client_id: &str,
    ) -> Result<DeviceCode> {
        let device_code_record = Self::find_by_device_code(pool, device_code)
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

    #[allow(dead_code)]
    pub async fn cleanup_expired(pool: &SqlitePool) -> Result<u64> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            DELETE FROM device_codes WHERE expires_at < ?
            "#,
        )
        .bind(now)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
