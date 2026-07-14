use axum::http::HeaderValue;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MIN_METRICS_BEARER_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
pub struct HttpSecurityConfig {
    pub max_request_body_bytes: usize,
    pub metrics_access: MetricsAccess,
}

impl HttpSecurityConfig {
    pub fn from_env() -> Result<Self, String> {
        let body_limit = optional_unicode_env("MAX_REQUEST_BODY_BYTES")?;
        let metrics_token = optional_unicode_env("METRICS_BEARER_TOKEN")?;
        Self::from_values(body_limit.as_deref(), metrics_token.as_deref())
    }

    fn from_values(body_limit: Option<&str>, metrics_token: Option<&str>) -> Result<Self, String> {
        let max_request_body_bytes = match body_limit {
            None | Some("") => DEFAULT_MAX_REQUEST_BODY_BYTES,
            Some(raw) => raw.parse::<usize>().map_err(|_| {
                "MAX_REQUEST_BODY_BYTES must be a positive integer number of bytes".to_string()
            })?,
        };
        if max_request_body_bytes == 0 {
            return Err("MAX_REQUEST_BODY_BYTES must be greater than zero".to_string());
        }

        let metrics_access = MetricsAccess::from_token(metrics_token)?;
        Ok(Self {
            max_request_body_bytes,
            metrics_access,
        })
    }

    pub fn request_body_limit_layer(&self) -> RequestBodyLimitLayer {
        RequestBodyLimitLayer::new(self.max_request_body_bytes)
    }
}

fn optional_unicode_env(key: &str) -> Result<Option<String>, String> {
    match std::env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{key} must contain valid UTF-8")),
    }
}

#[derive(Clone)]
pub struct MetricsAccess {
    expected_token_digest: Option<[u8; 32]>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MetricsAuthorization {
    Authorized,
    Unauthorized,
    Disabled,
}

impl MetricsAccess {
    fn from_token(token: Option<&str>) -> Result<Self, String> {
        let token = token.filter(|token| !token.is_empty());
        if let Some(token) = token {
            if token.len() < MIN_METRICS_BEARER_TOKEN_BYTES {
                return Err(format!(
                    "METRICS_BEARER_TOKEN must contain at least {MIN_METRICS_BEARER_TOKEN_BYTES} bytes"
                ));
            }
            if !token.is_ascii() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
                return Err(
                    "METRICS_BEARER_TOKEN must be ASCII and contain no whitespace".to_string(),
                );
            }
        }

        Ok(Self {
            expected_token_digest: token.map(token_digest),
        })
    }

    pub fn authorize(&self, authorization: Option<&HeaderValue>) -> MetricsAuthorization {
        let Some(expected) = self.expected_token_digest else {
            return MetricsAuthorization::Disabled;
        };
        let Some(presented) = authorization
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return MetricsAuthorization::Unauthorized;
        };

        let presented = token_digest(presented);
        if bool::from(presented.ct_eq(&expected)) {
            MetricsAuthorization::Authorized
        } else {
            MetricsAuthorization::Unauthorized
        }
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn defaults_to_one_mib_and_disabled_metrics() {
        let config = HttpSecurityConfig::from_values(None, None).expect("default config");
        assert_eq!(
            config.max_request_body_bytes,
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(
            config.metrics_access.authorize(None),
            MetricsAuthorization::Disabled
        );
    }

    #[test]
    fn rejects_invalid_security_configuration() {
        assert!(HttpSecurityConfig::from_values(Some("0"), None).is_err());
        assert!(HttpSecurityConfig::from_values(Some("many"), None).is_err());
        assert!(HttpSecurityConfig::from_values(None, Some("too-short")).is_err());
        assert!(
            HttpSecurityConfig::from_values(None, Some("0123456789abcdef0123456789abc def"))
                .is_err()
        );
    }

    #[test]
    fn metrics_requires_the_exact_bearer_token() {
        let config = HttpSecurityConfig::from_values(None, Some(TEST_TOKEN)).expect("valid token");
        let valid = HeaderValue::from_str(&format!("Bearer {TEST_TOKEN}")).expect("valid header");
        let invalid = HeaderValue::from_static("Bearer 0123456789abcdef0123456789abcdeg");

        assert_eq!(
            config.metrics_access.authorize(Some(&valid)),
            MetricsAuthorization::Authorized
        );
        assert_eq!(
            config.metrics_access.authorize(Some(&invalid)),
            MetricsAuthorization::Unauthorized
        );
        assert_eq!(
            config.metrics_access.authorize(None),
            MetricsAuthorization::Unauthorized
        );
    }

    #[tokio::test]
    async fn request_body_limit_rejects_oversized_streams() {
        let config = HttpSecurityConfig::from_values(Some("8"), None).expect("valid config");
        let app = Router::new()
            .route("/", post(|_: Bytes| async { StatusCode::NO_CONTENT }))
            .route("/health", get(|| async { StatusCode::OK }))
            .layer(config.request_body_limit_layer());

        let bodyless_probe = app
            .clone()
            .oneshot(
                Request::get("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(bodyless_probe.status(), StatusCode::OK);

        let within_limit = app
            .clone()
            .oneshot(
                Request::post("/")
                    .body(Body::from("12345678"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(within_limit.status(), StatusCode::NO_CONTENT);

        let over_limit = app
            .oneshot(
                Request::post("/")
                    .body(Body::from("123456789"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(over_limit.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
