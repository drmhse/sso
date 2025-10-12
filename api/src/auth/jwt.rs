use crate::error::{AppError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
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
    key_id: String,
}

impl JwtService {
    pub fn new(
        private_key_base64: &str,
        public_key_base64: &str,
        expiration_hours: i64,
        key_id: &str,
    ) -> Result<Self> {
        let private_key_pem = STANDARD
            .decode(private_key_base64)
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to decode private key: {}", e))
            })?;
        let public_key_pem = STANDARD
            .decode(public_key_base64)
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to decode public key: {}", e))
            })?;

        let encoding_key = EncodingKey::from_rsa_pem(&private_key_pem).map_err(|e| {
            AppError::InternalServerError(format!("Failed to create encoding key: {}", e))
        })?;
        let decoding_key = DecodingKey::from_rsa_pem(&public_key_pem).map_err(|e| {
            AppError::InternalServerError(format!("Failed to create decoding key: {}", e))
        })?;

        Ok(Self {
            encoding_key,
            decoding_key,
            expiration_hours,
            key_id: key_id.to_string(),
        })
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

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.encoding_key).map_err(AppError::Jwt)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
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
        let private_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ0dlSHhCSHJkRE9wR3cKLzNOcGhkK2JhRTNEaGNac3F3cE83Tm0rZUxsMGNkWERINUc2eXBURW1oS25LLzYrRmM4UE95SnB1R0ZORll5NAoyUUd4VVBiekJyeTZ3ay80TWMwV09mNXlKOFh6djlLRGcyM0pObk1OLys1cExLT0UzTS9BbSs2aVpYd1ZUMGJ0ClR4aU9nNlppajlLS3hZck9ZSitqWEE3aE1xWHFwc1h5b2t4d3pKLzM3eG96QktpRnVycGtad2tGZzQ0cldHSTYKalovN0pxRWszSHM0djdUcGZiWUovWnRzcndhYnduMWdzZDA4enpLVXNQTURGelpuWTJwTGorUG5tNWJTd1ZuTgpWSDRxTjBMNWtYUWxQMVZmQ1VhTTV1YnVxenE0c3FPeVJ0aTFRYTI0dG1qMS9jeXJKRno2OFhtT1RyZm1Cbmc3CmZMa0IzdHM3QWdNQkFBRUNnZ0VBRCtLMlJHMGxWNUd1T2h1R0hna0hndnVkOVlOZFpHTmZzRFk3MGt3VWEwU3kKd2o1OXFwN3ZBZVlmczZtM1g1WlhvK1FucXhkSFFMZDkxeTBsRFl1cE9NbVZkeUg5d2k0dW5ROFVna0RmbWtMbQowc3d1ZStSQ1VGSSttYzhyc1hEeWhyMnZ3Y3M5RHVRUzFzc095c1hwQnpZWURjdkxjTzVVNkQ2M3IvUHZTaS9tCkFTM051VlMycWNYOFd1RGt0Q3hKRFRxQjREa2ZWRnpoUFV2NWJmaThHWVUwZ2Z3TmZMYUpHdmcyUTdSQzl6eC8KejBncVNZTnZaMllWem8zY3Jvckh2S2F1M0RhcVZpRG1sVTBubEtncFJxbXZCNG9IeHRYcVgxNnY0OEs4WGwxRAo5V3lFNUZYanJEUWhPZWNWazJ6NDJDdWp1TjZlVlppeUk5blpBV2JBM1FLQmdRQzV6eVZCMHE0bkNrNm9pWitSCnNkWkkvb3k1ajY3VkJ0T0ZhNUpzS092UGtYMjlQclA1ZlN0dXFNNklDUFNmMWVwTmI5REZrN2gwVENqbmhuRHEKYWpJeDZUMk5GWWJMTEo0L05iS0RnNDI3UHdzTzcrbFAxM0l1eDdvUi94R2RpZFExcUwzdVdVSlB5cFZKM2xXTgpPWkk2U1Z2dU4wY0wzNnFaUkdhREExWGFSd0tCZ1FDNVJKbGF1emx5MndpTUNxVFRlSUV6TGNibHV3eHFROVN1CkFQUDFoWkVxMVdMOERvbitqZUIyTkxwRTNUWG9QRzRncVNxSTFxS05vSTE0ekNVWjlyMTkvcjg2eEkvaGZ1UXYKRkxJZjQ2TnJ0MzdMZnNNTGxGL3dIQWxrc05JYU9TQTFkZ3ZORC80Rm9BNkwzeldYNGdyTFZjQVIvK2c4ZmlIKwpJTWNJelVJOWJRS0JnRGhWQ2VtYjB2cTVFRUhlZjRjdlVGVU8vMkVlbzVXb0hTYTlCMFpOWGJpdlZseXlqdVBiCncvZ25xMzNvb1NsNE5ESEg3WmFKQTRvV3NPd0lnV0ZBVXZsNHloVms2bG5jckJsajBUdzMvUmRBdEx5UmxiMkUKQnZVUnptSzRYd0hSRUlvNEgyVU1vS01LT3hxTEVvcmZZbXJUWk5DaTU2STg3RDdOVXZyelh1cnZBb0dBVk5tZApIcGZHdk5xaDlIbGZlZGFqM1l1bW4wcG1hamk4ckNDVm1xbmNqWENEVUF0Y21lL2lrR0NmdXJCUll4WmlIYVU4CmJNVllWMkxqeUNJL0Q4QVlreDdiK0E5VUVpTnFZRUdyUHIyajk4NW5UTTIyaUpRZ3lEZ2UrVFdlVkJJN3RTQm0KVVRsMHpxQzZhTWNHcFpRSis0dy9WajhNM3IrcDA5aXhMMC9LZVpVQ2dZRUFnTGQyeEJROE1Cam9POG44ci8ycgptTTl3cWpzTXpqa1JzN3l1Vi9tMEZEOXFEemI2aGlMMmpGZHBpeXh6Yzg4NzNmdmVkaGxZSGg0T2svN0JpdDk3CjV3Wjh0TVFaZ3BCUzBZMkZ5dGE3cnZzeXNQclhKRmk5bXZSSnNsWk9DZmtjaXdLYU03S1BXM2c1cktsWk1JV08KSzFGeXBzOXpRS1ZvSkRWdkJlQ3BaV289Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K";
        let public_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFobmg4UVI2M1F6cVJzUDl6YVlYZgptMmhOdzRYR2JLc0tUdXpadm5pNWRISFZ3eCtSdXNxVXhKb1NweXYrdmhYUER6c2lhYmhoVFJXTXVOa0JzVkQyCjh3YTh1c0pQK0RITkZqbitjaWZGODcvU2c0TnR5VFp6RGYvdWFTeWpoTnpQd0p2dW9tVjhGVTlHN1U4WWpvT20KWW8vU2lzV0t6bUNmbzF3TzRUS2w2cWJGOHFKTWNNeWY5KzhhTXdTb2hicTZaR2NKQllPT0sxaGlPbzJmK3lhaApKTng3T0wrMDZYMjJDZjJiYks4R204SjlZTEhkUE04eWxMRHpBeGMyWjJOcVM0L2o1NXVXMHNGWnpWUitLamRDCitaRjBKVDlWWHdsR2pPYm03cXM2dUxLanNrYll0VUd0dUxabzlmM01xeVJjK3ZGNWprNjM1Z1o0TzN5NUFkN2IKT3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
        let jwt_service = JwtService::new(private_key, public_key, 24, "test-key-id").unwrap();
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
