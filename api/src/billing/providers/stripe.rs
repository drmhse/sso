//! Stripe billing provider implementation using Stripe's REST API directly.

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
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;
const STRIPE_WEBHOOK_TOLERANCE_SECONDS: i64 = 300;

pub struct StripeProvider {
    api_key: String,
    webhook_secret: String,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct StripeIdResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct StripeUrlResponse {
    id: Option<String>,
    url: String,
}

impl StripeProvider {
    pub fn new(api_key: String, webhook_secret: String) -> Self {
        Self::new_with_base_url(api_key, webhook_secret, "https://api.stripe.com")
    }

    pub fn new_with_base_url(api_key: String, webhook_secret: String, base_url: &str) -> Self {
        Self {
            api_key,
            webhook_secret,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    async fn post_form<T>(&self, path: &str, form: Vec<(String, String)>) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.extend_pairs(
                form.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            );
            serializer.finish().into_bytes()
        };
        let headers = vec![
            (
                "authorization".to_string(),
                format!("Bearer {}", self.api_key).into_bytes(),
            ),
            (
                "content-type".to_string(),
                b"application/x-www-form-urlencoded".to_vec(),
            ),
        ];
        let response = SafeHttpClient::new()
            .map_err(|_| AppError::Billing("Stripe request could not be started".to_string()))?
            .request_with_owned_headers(reqwest::Method::POST, &self.endpoint(path), body, headers)
            .await
            .map_err(|_| AppError::Billing("Stripe API request failed".to_string()))?;

        Self::decode_response(response).await
    }

    async fn decode_response<T>(response: reqwest::Response) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let (status, body) =
            SafeHttpClient::read_body_limited(response, MAX_BILLING_RESPONSE_BYTES)
                .await
                .map_err(|_| AppError::Billing("Stripe API response was rejected".to_string()))?;

        if !status.is_success() {
            return Err(AppError::Billing(format!(
                "Stripe API request failed with status {}",
                status.as_u16()
            )));
        }

        serde_json::from_slice(&body)
            .map_err(|_| AppError::Billing("Stripe API returned an invalid response".to_string()))
    }

    fn push_metadata(form: &mut Vec<(String, String)>, metadata: HashMap<String, String>) {
        for (key, value) in metadata {
            form.push((format!("metadata[{}]", key), value));
        }
    }

    fn normalize_subscription_status(status: Option<&str>) -> SubscriptionStatus {
        match status {
            Some("active") => SubscriptionStatus::Active,
            Some("past_due") => SubscriptionStatus::PastDue,
            Some("canceled") => SubscriptionStatus::Canceled,
            Some("trialing") => SubscriptionStatus::Trialing,
            Some("incomplete") => SubscriptionStatus::Incomplete,
            Some("incomplete_expired") => SubscriptionStatus::Canceled,
            Some("unpaid") | Some("paused") => SubscriptionStatus::Suspended,
            _ => SubscriptionStatus::Unknown,
        }
    }

    fn expandable_id(value: Option<&Value>) -> Option<String> {
        value.and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.get("id").and_then(Value::as_str).map(str::to_string))
        })
    }

    fn metadata(value: &Value) -> HashMap<String, String> {
        value
            .get("metadata")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn subscription_product_id(subscription: &Value) -> Option<String> {
        subscription
            .pointer("/items/data/0/price/product")
            .and_then(|product| {
                product.as_str().map(str::to_string).or_else(|| {
                    product
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
            })
    }

    fn parse_stripe_event(&self, event: Value) -> BillingEvent {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let object = event.pointer("/data/object").unwrap_or(&Value::Null);

        match event_type.as_str() {
            "checkout.session.completed" => BillingEvent::CheckoutCompleted {
                external_customer_id: Self::expandable_id(object.get("customer")),
                external_subscription_id: Self::expandable_id(object.get("subscription")),
            },
            "customer.subscription.created" => self.parse_subscription_event(object, true),
            "customer.subscription.updated" => self.parse_subscription_event(object, false),
            "customer.subscription.deleted" => BillingEvent::SubscriptionDeleted {
                external_customer_id: Self::expandable_id(object.get("customer"))
                    .unwrap_or_default(),
                external_subscription_id: object
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            "invoice.payment_succeeded" => BillingEvent::PaymentSucceeded {
                external_customer_id: Self::expandable_id(object.get("customer"))
                    .unwrap_or_default(),
            },
            "invoice.payment_failed" => BillingEvent::PaymentFailed {
                external_customer_id: Self::expandable_id(object.get("customer"))
                    .unwrap_or_default(),
                attempt_count: object
                    .get("attempt_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32,
            },
            _ => BillingEvent::Unhandled { event_type },
        }
    }

    fn parse_subscription_event(&self, subscription: &Value, created: bool) -> BillingEvent {
        let external_customer_id =
            Self::expandable_id(subscription.get("customer")).unwrap_or_default();
        let external_subscription_id = subscription
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let current_period_end = subscription
            .get("current_period_end")
            .and_then(Value::as_i64)
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .unwrap_or_else(Utc::now);
        let external_product_id = Self::subscription_product_id(subscription);
        let status =
            Self::normalize_subscription_status(subscription.get("status").and_then(Value::as_str));
        let metadata = Self::metadata(subscription);

        if created {
            BillingEvent::SubscriptionCreated {
                external_customer_id,
                external_subscription_id,
                external_product_id,
                status,
                current_period_end,
                metadata,
            }
        } else {
            BillingEvent::SubscriptionUpdated {
                external_customer_id,
                external_subscription_id,
                external_product_id,
                status,
                current_period_end,
                metadata,
            }
        }
    }

    fn verify_signature(&self, header: &str, payload: &str) -> Result<()> {
        let mut timestamp = None;
        let mut signatures = Vec::new();

        for part in header.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "t" => timestamp = Some(value),
                    "v1" => signatures.push(value),
                    _ => {}
                }
            }
        }

        let timestamp = timestamp
            .ok_or_else(|| AppError::BadRequest("Missing Stripe webhook timestamp".to_string()))?;
        let timestamp_seconds = timestamp
            .parse::<i64>()
            .map_err(|_| AppError::BadRequest("Invalid Stripe webhook timestamp".to_string()))?;
        let now = Utc::now().timestamp();
        if (now - timestamp_seconds).abs() > STRIPE_WEBHOOK_TOLERANCE_SECONDS {
            return Err(AppError::Billing(
                "Webhook verification failed: timestamp outside tolerance".to_string(),
            ));
        }
        if signatures.is_empty() {
            return Err(AppError::BadRequest(
                "Missing Stripe webhook signature".to_string(),
            ));
        }

        let signed_payload = format!("{}.{}", timestamp, payload);
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| AppError::Billing("Invalid Stripe webhook secret".to_string()))?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        if signatures.iter().any(|signature| {
            signature.len() == expected.len()
                && constant_time_eq(signature.as_bytes(), expected.as_bytes())
        }) {
            Ok(())
        } else {
            Err(AppError::Billing(
                "Webhook verification failed: invalid signature".to_string(),
            ))
        }
    }
}

#[async_trait]
impl BillingProvider for StripeProvider {
    fn provider_type(&self) -> BillingProviderType {
        BillingProviderType::Stripe
    }

    async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String> {
        let mut form = vec![
            ("name".to_string(), request.org_name),
            ("metadata[org_id]".to_string(), request.org_id),
        ];
        if let Some(email) = request.email {
            form.push(("email".to_string(), email));
        }
        Self::push_metadata(&mut form, request.metadata);

        let customer: StripeIdResponse = self.post_form("/v1/customers", form).await?;
        Ok(customer.id)
    }

    async fn create_checkout_session(
        &self,
        request: CreateCheckoutRequest,
    ) -> Result<CheckoutResult> {
        let mut form = vec![
            ("customer".to_string(), request.external_customer_id),
            ("mode".to_string(), "subscription".to_string()),
            ("success_url".to_string(), request.success_url),
            ("cancel_url".to_string(), request.cancel_url),
            ("line_items[0][price]".to_string(), request.price_id),
            ("line_items[0][quantity]".to_string(), "1".to_string()),
        ];
        Self::push_metadata(&mut form, request.metadata);

        let session: StripeUrlResponse = self.post_form("/v1/checkout/sessions", form).await?;
        Ok(CheckoutResult {
            url: session.url,
            session_id: session.id.unwrap_or_default(),
        })
    }

    async fn create_portal_session(
        &self,
        external_customer_id: &str,
        return_url: &str,
    ) -> Result<PortalResult> {
        let form = vec![
            ("customer".to_string(), external_customer_id.to_string()),
            ("return_url".to_string(), return_url.to_string()),
        ];
        let session: StripeUrlResponse =
            self.post_form("/v1/billing_portal/sessions", form).await?;
        Ok(PortalResult { url: session.url })
    }

    fn verify_webhook(&self, headers: &HeaderMap, body: &Bytes) -> Result<BillingEvent> {
        let payload = String::from_utf8(body.to_vec())
            .map_err(|_| AppError::BadRequest("Invalid payload encoding".to_string()))?;

        let is_test_mode = std::env::var("STRIPE_WEBHOOK_TEST_MODE")
            .unwrap_or_default()
            .to_lowercase()
            == "true";

        if !is_test_mode {
            let signature = headers
                .get("stripe-signature")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| {
                    AppError::BadRequest("Missing stripe-signature header".to_string())
                })?;
            self.verify_signature(signature, &payload)?;
        } else if !headers.contains_key("stripe-signature") {
            return Err(AppError::BadRequest(
                "Missing stripe-signature header".to_string(),
            ));
        }

        let event = serde_json::from_str(&payload)
            .map_err(|e| AppError::BadRequest(format!("Invalid webhook JSON: {}", e)))?;
        Ok(self.parse_stripe_event(event))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn configured_private_base_url_fails_closed_with_redacted_error() {
        let api_key = "sk_test_must_not_leak";
        let base_url = "http://127.0.0.1:9/private-stripe-endpoint";
        let provider = StripeProvider::new_with_base_url(
            api_key.to_string(),
            "webhook-secret".to_string(),
            base_url,
        );

        let error = provider
            .post_form::<StripeIdResponse>("/v1/customers", Vec::new())
            .await
            .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Stripe API request failed"));
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

        let error = StripeProvider::decode_response::<StripeIdResponse>(response)
            .await
            .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Stripe API response was rejected"));
        assert!(!message.contains("secret-response-body"));
        server.await.unwrap();
    }
}
