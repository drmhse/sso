//! Polar billing provider implementation.
//!
//! Polar is a modern alternative to Stripe focused on open source projects.
//! This is a stub implementation that can be extended when Polar support is needed.

use crate::billing::models::{
    BillingEvent, BillingProviderType, CheckoutResult, CreateCheckoutRequest,
    CreateCustomerRequest, PortalResult, SubscriptionStatus,
};
use crate::billing::traits::BillingProvider;
use crate::error::{AppError, Result};
use crate::services::safe_http::{SafeHttpClient, MAX_BILLING_RESPONSE_BYTES};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::HeaderMap;
use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;

pub struct PolarProvider {
    api_key: String,
    webhook_secret: String,
    #[allow(dead_code)]
    base_url: String,
}

impl PolarProvider {
    pub fn new(api_key: String, webhook_secret: String) -> Self {
        Self {
            api_key,
            webhook_secret,
            base_url: "https://api.polar.sh".to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn new_with_base_url(api_key: String, webhook_secret: String, base_url: &str) -> Self {
        Self {
            api_key,
            webhook_secret,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl BillingProvider for PolarProvider {
    fn provider_type(&self) -> BillingProviderType {
        BillingProviderType::Polar
    }

    async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String> {
        // Polar doesn't have a dedicated customer creation endpoint
        // Customers are automatically created during checkout with external_customer_id
        // We return the org_id which will be used as external_customer_id during checkout
        // The actual customer record in Polar will be created when the first checkout completes

        // Validate that we have required fields
        if request.org_id.is_empty() {
            return Err(AppError::Billing(
                "org_id is required for Polar customer creation".to_string(),
            ));
        }

        // Return the org_id as the external customer ID
        // This will be used in create_checkout_session
        Ok(request.org_id)
    }

    async fn create_checkout_session(
        &self,
        request: CreateCheckoutRequest,
    ) -> Result<CheckoutResult> {
        // Create checkout session via Polar API
        // POST /v1/checkouts/
        let mut payload = serde_json::json!({
            "product_price_id": request.price_id,
            "success_url": request.success_url,
        });

        // Add external_customer_id if provided
        if !request.external_customer_id.is_empty() {
            payload["customer_metadata"] = serde_json::json!({
                "external_id": request.external_customer_id
            });
        }

        // Add metadata if provided
        if !request.metadata.is_empty() {
            if let Some(customer_metadata) = payload.get_mut("customer_metadata") {
                customer_metadata["metadata"] =
                    serde_json::to_value(&request.metadata).map_err(|e| {
                        AppError::Billing(format!("Failed to serialize metadata: {}", e))
                    })?;
            } else {
                payload["customer_metadata"] = serde_json::json!({
                    "metadata": request.metadata
                });
            }
        }

        #[derive(serde::Deserialize)]
        struct CheckoutResponse {
            id: String,
            url: String,
        }

        let response: CheckoutResponse = self
            .api_request(reqwest::Method::POST, "/v1/checkouts/", Some(payload))
            .await?;

        Ok(CheckoutResult {
            url: response.url,
            session_id: response.id,
        })
    }

    async fn create_portal_session(
        &self,
        external_customer_id: &str,
        _return_url: &str,
    ) -> Result<PortalResult> {
        // Create customer portal session via Polar API
        // POST /v1/customer-sessions/
        let payload = serde_json::json!({
            "customer_id": external_customer_id,
        });

        #[derive(serde::Deserialize)]
        struct CustomerSessionResponse {
            customer_portal_url: String,
        }

        let response: CustomerSessionResponse = self
            .api_request(
                reqwest::Method::POST,
                "/v1/customer-sessions/",
                Some(payload),
            )
            .await?;

        Ok(PortalResult {
            url: response.customer_portal_url,
        })
    }

    fn verify_webhook(&self, headers: &HeaderMap, body: &Bytes) -> Result<BillingEvent> {
        // Polar follows Standard Webhooks specification (Svix-compatible)
        // Required headers: svix-id, svix-timestamp, svix-signature
        let svix_id = headers
            .get("svix-id")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::BadRequest("Missing svix-id header".to_string()))?;

        let svix_timestamp = headers
            .get("svix-timestamp")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::BadRequest("Missing svix-timestamp header".to_string()))?;

        let svix_signature = headers
            .get("svix-signature")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::BadRequest("Missing svix-signature header".to_string()))?;

        // Validate timestamp to prevent replay attacks (allow 5 minute tolerance)
        let timestamp = svix_timestamp
            .parse::<i64>()
            .map_err(|_| AppError::BadRequest("Invalid svix-timestamp format".to_string()))?;

        let current_time = chrono::Utc::now().timestamp();
        let time_diff = (current_time - timestamp).abs();
        if time_diff > 300 {
            // 5 minutes
            return Err(AppError::BadRequest(
                "Webhook timestamp outside tolerance window".to_string(),
            ));
        }

        // Construct signed content: ${svix_id}.${svix_timestamp}.${body}
        let payload_str = std::str::from_utf8(body)
            .map_err(|_| AppError::BadRequest("Invalid payload encoding".to_string()))?;
        let signed_content = format!("{}.{}.{}", svix_id, svix_timestamp, payload_str);

        // Decode webhook secret (remove 'whsec_' prefix if present and base64 decode)
        let secret_base64 = if self.webhook_secret.starts_with("whsec_") {
            &self.webhook_secret[6..]
        } else {
            &self.webhook_secret
        };

        // Trim whitespace to be robust against env var formatting issues
        let secret_base64 = secret_base64.trim();

        let secret = base64::engine::general_purpose::STANDARD
            .decode(secret_base64)
            .map_err(|e| AppError::Billing(format!("Invalid webhook secret encoding: {}", e)))?;

        // Generate expected signature using HMAC-SHA256
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&secret)
            .map_err(|_| AppError::Billing("Invalid webhook secret".to_string()))?;
        mac.update(signed_content.as_bytes());
        let expected_signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        // Parse signature header (format: "v1,sig1= v2,sig2=")
        // We need to verify against any of the provided signatures
        let signatures: Vec<&str> = svix_signature
            .split_whitespace()
            .filter_map(|s| s.strip_prefix("v1,"))
            .collect();

        if signatures.is_empty() {
            return Err(AppError::BadRequest(
                "No valid v1 signatures found in header".to_string(),
            ));
        }

        // Constant-time comparison to prevent timing attacks
        let signature_valid = signatures.iter().any(|&sig| {
            use subtle::ConstantTimeEq;
            sig.as_bytes().ct_eq(expected_signature.as_bytes()).into()
        });

        if !signature_valid {
            return Err(AppError::Billing(
                "Webhook signature verification failed".to_string(),
            ));
        }

        // Parse and normalize the event
        let event: serde_json::Value = serde_json::from_str(payload_str)
            .map_err(|e| AppError::BadRequest(format!("Invalid webhook JSON: {}", e)))?;

        let event_type = event
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown");

        // Map Polar events to our normalized events
        self.parse_polar_event(event_type, &event)
    }
}

impl PolarProvider {
    /// Parse Polar webhook event into normalized billing event
    fn parse_polar_event(
        &self,
        event_type: &str,
        event: &serde_json::Value,
    ) -> Result<BillingEvent> {
        let data = event.get("data").ok_or_else(|| {
            AppError::BadRequest("Missing data field in Polar webhook".to_string())
        })?;

        match event_type {
            "customer.created" => {
                let customer_id = data
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::BadRequest("Missing customer id".to_string()))?
                    .to_string();

                let metadata = data
                    .get("metadata")
                    .and_then(|v| serde_json::from_value::<HashMap<String, String>>(v.clone()).ok())
                    .unwrap_or_default();

                Ok(BillingEvent::CustomerCreated {
                    external_customer_id: customer_id,
                    metadata,
                })
            }
            "subscription.created" | "subscription.active" => {
                self.parse_subscription_event(data, SubscriptionStatus::Active)
            }
            "subscription.updated" => {
                // Determine status from the subscription data
                let status_str = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("active");
                let status = Self::parse_subscription_status(status_str);
                self.parse_subscription_event(data, status)
            }
            "subscription.canceled" => {
                let customer_id = self.extract_customer_id(data)?;
                let subscription_id = self.extract_subscription_id(data)?;

                Ok(BillingEvent::SubscriptionDeleted {
                    external_customer_id: customer_id,
                    external_subscription_id: subscription_id,
                })
            }
            "subscription.revoked" => {
                let customer_id = self.extract_customer_id(data)?;
                let subscription_id = self.extract_subscription_id(data)?;

                Ok(BillingEvent::SubscriptionDeleted {
                    external_customer_id: customer_id,
                    external_subscription_id: subscription_id,
                })
            }
            "order.created" => {
                let customer_id = self.extract_customer_id(data)?;
                let subscription_id = data
                    .get("subscription_id")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                Ok(BillingEvent::CheckoutCompleted {
                    external_customer_id: Some(customer_id),
                    external_subscription_id: subscription_id,
                })
            }
            "order.paid" => {
                let customer_id = self.extract_customer_id(data)?;

                Ok(BillingEvent::PaymentSucceeded {
                    external_customer_id: customer_id,
                })
            }
            "order.refunded" => {
                let customer_id = self.extract_customer_id(data)?;

                Ok(BillingEvent::PaymentFailed {
                    external_customer_id: customer_id,
                    attempt_count: 0,
                })
            }
            _ => Ok(BillingEvent::Unhandled {
                event_type: format!("polar:{}", event_type),
            }),
        }
    }

    fn parse_subscription_event(
        &self,
        data: &serde_json::Value,
        status: SubscriptionStatus,
    ) -> Result<BillingEvent> {
        let customer_id = self.extract_customer_id(data)?;
        let subscription_id = self.extract_subscription_id(data)?;

        let product_id = data
            .get("product_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let current_period_end = data
            .get("current_period_end")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(Utc::now);

        let metadata = data
            .get("metadata")
            .and_then(|v| serde_json::from_value::<HashMap<String, String>>(v.clone()).ok())
            .unwrap_or_default();

        Ok(BillingEvent::SubscriptionUpdated {
            external_customer_id: customer_id,
            external_subscription_id: subscription_id,
            external_product_id: product_id,
            status,
            current_period_end,
            metadata,
        })
    }

    fn extract_customer_id(&self, data: &serde_json::Value) -> Result<String> {
        data.get("customer_id")
            .or_else(|| data.get("customer").and_then(|c| c.get("id")))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing customer_id in webhook data".to_string()))
            .map(String::from)
    }

    fn extract_subscription_id(&self, data: &serde_json::Value) -> Result<String> {
        data.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing subscription id".to_string()))
            .map(String::from)
    }

    fn parse_subscription_status(status: &str) -> SubscriptionStatus {
        match status.to_lowercase().as_str() {
            "active" => SubscriptionStatus::Active,
            "past_due" => SubscriptionStatus::PastDue,
            "canceled" => SubscriptionStatus::Canceled,
            "incomplete" => SubscriptionStatus::Incomplete,
            "trialing" => SubscriptionStatus::Trialing,
            "unpaid" => SubscriptionStatus::Suspended,
            _ => SubscriptionStatus::Unknown,
        }
    }

    async fn api_request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut headers = vec![(
            "authorization".to_string(),
            format!("Bearer {}", self.api_key).into_bytes(),
        )];
        let body = if let Some(body) = body {
            headers.push(("content-type".to_string(), b"application/json".to_vec()));
            serde_json::to_vec(&body)
                .map_err(|_| AppError::Billing("Polar request encoding failed".to_string()))?
        } else {
            Vec::new()
        };

        let response = SafeHttpClient::new()
            .map_err(|_| AppError::Billing("Polar request could not be started".to_string()))?
            .request_with_owned_headers(method, &url, body, headers)
            .await
            .map_err(|_| AppError::Billing("Polar API request failed".to_string()))?;

        Self::decode_response(response).await
    }

    async fn decode_response<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T> {
        let (status, body) =
            SafeHttpClient::read_body_limited(response, MAX_BILLING_RESPONSE_BYTES)
                .await
                .map_err(|_| AppError::Billing("Polar API response was rejected".to_string()))?;

        if !status.is_success() {
            return Err(AppError::Billing(format!(
                "Polar API request failed with status {}",
                status.as_u16()
            )));
        }

        serde_json::from_slice(&body)
            .map_err(|_| AppError::Billing("Polar API returned an invalid response".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn configured_private_base_url_fails_closed_with_redacted_error() {
        let api_key = "polar_key_must_not_leak";
        let base_url = "http://127.0.0.1:9/private-polar-endpoint";
        let provider = PolarProvider::new_with_base_url(
            api_key.to_string(),
            "webhook-secret".to_string(),
            base_url,
        );

        let error = provider
            .api_request::<serde_json::Value>(reqwest::Method::POST, "/v1/checkouts/", None)
            .await
            .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Polar API request failed"));
        assert!(!message.contains(api_key));
        assert!(!message.contains(base_url));
        assert!(!message.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_without_exposing_body_details() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let declared_size = MAX_BILLING_RESPONSE_BYTES + 1;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {declared_size}\r\n\r\nsecret-response-body"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();

        let error = PolarProvider::decode_response::<serde_json::Value>(response)
            .await
            .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Polar API response was rejected"));
        assert!(!message.contains("secret-response-body"));
        server.await.unwrap();
    }
}
