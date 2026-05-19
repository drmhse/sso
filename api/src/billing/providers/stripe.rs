//! Stripe billing provider implementation.

use crate::billing::models::{
    BillingEvent, BillingProviderType, CheckoutResult, CreateCheckoutRequest,
    CreateCustomerRequest, PortalResult, SubscriptionStatus,
};
use crate::billing::traits::BillingProvider;
use crate::error::{AppError, Result};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::HeaderMap;
use chrono::Utc;
use std::collections::HashMap;
use stripe::{
    BillingPortalSession, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCustomer, Customer, Event,
    EventObject, EventType, Webhook,
};

pub struct StripeProvider {
    client: Client,
    webhook_secret: String,
}

impl StripeProvider {
    pub fn new(api_key: String, webhook_secret: String) -> Self {
        let client = Client::new(api_key);
        Self {
            client,
            webhook_secret,
        }
    }

    pub fn new_with_base_url(api_key: String, webhook_secret: String, base_url: &str) -> Self {
        let client = Client::from_url(base_url, api_key);
        Self {
            client,
            webhook_secret,
        }
    }

    /// Convert Stripe subscription status to normalized status
    fn normalize_subscription_status(status: &stripe::SubscriptionStatus) -> SubscriptionStatus {
        match status {
            stripe::SubscriptionStatus::Active => SubscriptionStatus::Active,
            stripe::SubscriptionStatus::PastDue => SubscriptionStatus::PastDue,
            stripe::SubscriptionStatus::Canceled => SubscriptionStatus::Canceled,
            stripe::SubscriptionStatus::Trialing => SubscriptionStatus::Trialing,
            stripe::SubscriptionStatus::Incomplete => SubscriptionStatus::Incomplete,
            stripe::SubscriptionStatus::IncompleteExpired => SubscriptionStatus::Canceled,
            stripe::SubscriptionStatus::Unpaid => SubscriptionStatus::Suspended,
            stripe::SubscriptionStatus::Paused => SubscriptionStatus::Suspended,
        }
    }

    /// Parse Stripe event into normalized billing event
    fn parse_stripe_event(&self, event: Event) -> BillingEvent {
        match event.type_ {
            EventType::CheckoutSessionCompleted => {
                if let EventObject::CheckoutSession(session) = event.data.object {
                    BillingEvent::CheckoutCompleted {
                        external_customer_id: session.customer.map(|c| match c {
                            stripe::Expandable::Id(id) => id.to_string(),
                            stripe::Expandable::Object(obj) => obj.id.to_string(),
                        }),
                        external_subscription_id: session.subscription.map(|s| match s {
                            stripe::Expandable::Id(id) => id.to_string(),
                            stripe::Expandable::Object(obj) => obj.id.to_string(),
                        }),
                    }
                } else {
                    BillingEvent::Unhandled {
                        event_type: event.type_.to_string(),
                    }
                }
            }
            EventType::CustomerSubscriptionCreated => {
                if let EventObject::Subscription(subscription) = event.data.object {
                    let customer_id = match &subscription.customer {
                        stripe::Expandable::Id(id) => id.to_string(),
                        stripe::Expandable::Object(obj) => obj.id.to_string(),
                    };

                    let current_period_end =
                        chrono::DateTime::from_timestamp(subscription.current_period_end, 0)
                            .unwrap_or_else(Utc::now);

                    BillingEvent::SubscriptionCreated {
                        external_customer_id: customer_id,
                        external_subscription_id: subscription.id.to_string(),
                        external_product_id: subscription
                            .items
                            .data
                            .first()
                            .and_then(|item| item.price.as_ref())
                            .and_then(|price| price.product.as_ref())
                            .map(|p| match p {
                                stripe::Expandable::Id(id) => id.to_string(),
                                stripe::Expandable::Object(obj) => obj.id.to_string(),
                            }),
                        status: Self::normalize_subscription_status(&subscription.status),
                        current_period_end,
                        metadata: subscription.metadata.clone(),
                    }
                } else {
                    BillingEvent::Unhandled {
                        event_type: event.type_.to_string(),
                    }
                }
            }
            EventType::CustomerSubscriptionUpdated => {
                if let EventObject::Subscription(subscription) = event.data.object {
                    let customer_id = match &subscription.customer {
                        stripe::Expandable::Id(id) => id.to_string(),
                        stripe::Expandable::Object(obj) => obj.id.to_string(),
                    };

                    let current_period_end =
                        chrono::DateTime::from_timestamp(subscription.current_period_end, 0)
                            .unwrap_or_else(Utc::now);

                    BillingEvent::SubscriptionUpdated {
                        external_customer_id: customer_id,
                        external_subscription_id: subscription.id.to_string(),
                        external_product_id: subscription
                            .items
                            .data
                            .first()
                            .and_then(|item| item.price.as_ref())
                            .and_then(|price| price.product.as_ref())
                            .map(|p| match p {
                                stripe::Expandable::Id(id) => id.to_string(),
                                stripe::Expandable::Object(obj) => obj.id.to_string(),
                            }),
                        status: Self::normalize_subscription_status(&subscription.status),
                        current_period_end,
                        metadata: subscription.metadata.clone(),
                    }
                } else {
                    BillingEvent::Unhandled {
                        event_type: event.type_.to_string(),
                    }
                }
            }
            EventType::CustomerSubscriptionDeleted => {
                if let EventObject::Subscription(subscription) = event.data.object {
                    let customer_id = match &subscription.customer {
                        stripe::Expandable::Id(id) => id.to_string(),
                        stripe::Expandable::Object(obj) => obj.id.to_string(),
                    };

                    BillingEvent::SubscriptionDeleted {
                        external_customer_id: customer_id,
                        external_subscription_id: subscription.id.to_string(),
                    }
                } else {
                    BillingEvent::Unhandled {
                        event_type: event.type_.to_string(),
                    }
                }
            }
            EventType::InvoicePaymentSucceeded => {
                if let EventObject::Invoice(invoice) = event.data.object {
                    let customer_id = invoice
                        .customer
                        .map(|c| match c {
                            stripe::Expandable::Id(id) => id.to_string(),
                            stripe::Expandable::Object(obj) => obj.id.to_string(),
                        })
                        .unwrap_or_default();

                    BillingEvent::PaymentSucceeded {
                        external_customer_id: customer_id,
                    }
                } else {
                    BillingEvent::Unhandled {
                        event_type: event.type_.to_string(),
                    }
                }
            }
            EventType::InvoicePaymentFailed => {
                if let EventObject::Invoice(invoice) = event.data.object {
                    let customer_id = invoice
                        .customer
                        .map(|c| match c {
                            stripe::Expandable::Id(id) => id.to_string(),
                            stripe::Expandable::Object(obj) => obj.id.to_string(),
                        })
                        .unwrap_or_default();

                    BillingEvent::PaymentFailed {
                        external_customer_id: customer_id,
                        attempt_count: invoice.attempt_count.unwrap_or(0) as u32,
                    }
                } else {
                    BillingEvent::Unhandled {
                        event_type: event.type_.to_string(),
                    }
                }
            }
            _ => BillingEvent::Unhandled {
                event_type: event.type_.to_string(),
            },
        }
    }
}

#[async_trait]
impl BillingProvider for StripeProvider {
    fn provider_type(&self) -> BillingProviderType {
        BillingProviderType::Stripe
    }

    async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String> {
        let mut params = CreateCustomer::new();
        params.name = Some(&request.org_name);

        // Build metadata with org_id
        let mut metadata: HashMap<String, String> = request.metadata;
        metadata.insert("org_id".to_string(), request.org_id.clone());

        params.metadata = Some(
            metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );

        if let Some(ref email) = request.email {
            params.email = Some(email);
        }

        let customer = Customer::create(&self.client, params)
            .await
            .map_err(|e| AppError::Billing(format!("Failed to create Stripe customer: {}", e)))?;

        Ok(customer.id.to_string())
    }

    async fn create_checkout_session(
        &self,
        request: CreateCheckoutRequest,
    ) -> Result<CheckoutResult> {
        let mut params = CreateCheckoutSession::new();
        params.customer = Some(
            request
                .external_customer_id
                .parse()
                .map_err(|_| AppError::Billing("Invalid customer ID".to_string()))?,
        );
        params.mode = Some(CheckoutSessionMode::Subscription);
        params.success_url = Some(&request.success_url);
        params.cancel_url = Some(&request.cancel_url);
        params.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(request.price_id.clone()),
            quantity: Some(1),
            ..Default::default()
        }]);
        params.metadata = Some(request.metadata.into_iter().collect());

        let session = CheckoutSession::create(&self.client, params)
            .await
            .map_err(|e| AppError::Billing(format!("Failed to create checkout session: {}", e)))?;

        Ok(CheckoutResult {
            url: session.url.unwrap_or_default(),
            session_id: session.id.to_string(),
        })
    }

    async fn create_portal_session(
        &self,
        external_customer_id: &str,
        return_url: &str,
    ) -> Result<PortalResult> {
        let mut params = CreateBillingPortalSession::new(
            external_customer_id
                .parse()
                .map_err(|_| AppError::Billing("Invalid customer ID".to_string()))?,
        );
        params.return_url = Some(return_url);

        let session = BillingPortalSession::create(&self.client, params)
            .await
            .map_err(|e| AppError::Billing(format!("Failed to create portal session: {}", e)))?;

        Ok(PortalResult { url: session.url })
    }

    fn verify_webhook(&self, headers: &HeaderMap, body: &Bytes) -> Result<BillingEvent> {
        let payload = String::from_utf8(body.to_vec())
            .map_err(|_| AppError::BadRequest("Invalid payload encoding".to_string()))?;

        // Check if we're in test mode (bypass signature verification)
        let is_test_mode = std::env::var("STRIPE_WEBHOOK_TEST_MODE")
            .unwrap_or_default()
            .to_lowercase()
            == "true";

        let event = if is_test_mode {
            // In test mode, verify signature header is present but don't validate it
            if !headers.contains_key("stripe-signature") {
                return Err(AppError::BadRequest(
                    "Missing stripe-signature header".to_string(),
                ));
            }

            // Parse the event directly without signature verification
            serde_json::from_str(&payload)
                .map_err(|e| AppError::BadRequest(format!("Invalid webhook JSON: {}", e)))?
        } else {
            // Production mode: require and verify signature
            let signature = headers
                .get("stripe-signature")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| {
                    AppError::BadRequest("Missing stripe-signature header".to_string())
                })?;

            Webhook::construct_event(&payload, signature, &self.webhook_secret)
                .map_err(|e| AppError::Billing(format!("Webhook verification failed: {}", e)))?
        };

        Ok(self.parse_stripe_event(event))
    }
}
