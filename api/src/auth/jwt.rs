use crate::error::{AppError, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,             // user_id (required)
    pub email: String,           // user email (required)
    pub is_platform_owner: bool, // platform owner flag (required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>, // org_slug (optional, for service-specific JWTs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // service_slug (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>, // plan_name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>, // plan features (optional)
    pub exp: i64,                // expiration timestamp
    pub iat: i64,                // issued at timestamp
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiration_hours: i64,
}

impl JwtService {
    pub fn new(secret: &str, expiration_hours: i64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            expiration_hours,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_token(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        plan_name: Option<&str>,
        features: Option<Vec<String>>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            is_platform_owner,
            org: org_slug.map(|s| s.to_string()),
            service: service_slug.map(|s| s.to_string()),
            plan: plan_name.map(|s| s.to_string()),
            features,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(AppError::Jwt)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(AppError::Jwt)?;

        // Check if token is expired
        let now = Utc::now().timestamp();
        if token_data.claims.exp < now {
            return Err(AppError::TokenExpired);
        }

        Ok(token_data.claims)
    }

    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_creation_and_validation() {
        let jwt_service = JwtService::new("test_secret", 24);
        let features = vec!["export_csv".to_string(), "realtime_dashboards".to_string()];

        let token = jwt_service
            .create_token(
                "user_123",
                "user@example.com",
                false,
                Some("acme-corp"),
                Some("analytics"),
                Some("pro"),
                Some(features.clone()),
            )
            .unwrap();

        let claims = jwt_service.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user_123");
        assert_eq!(claims.email, "user@example.com");
        assert!(!claims.is_platform_owner);
        assert_eq!(claims.org, Some("acme-corp".to_string()));
        assert_eq!(claims.service, Some("analytics".to_string()));
        assert_eq!(claims.plan, Some("pro".to_string()));
        assert_eq!(claims.features, Some(features));
    }

    #[test]
    fn test_token_hash() {
        let token = "test_token_123";
        let hash = JwtService::hash_token(token);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars
    }
}
