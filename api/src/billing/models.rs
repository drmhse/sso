//! Unified billing models for provider-agnostic billing operations.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents which billing provider is being used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BillingProviderType {
    Disabled,
    Stripe,
    Polar,
}

impl std::fmt::Display for BillingProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BillingProviderType::Disabled => write!(f, "none"),
            BillingProviderType::Stripe => write!(f, "stripe"),
            BillingProviderType::Polar => write!(f, "polar"),
        }
    }
}

impl std::str::FromStr for BillingProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "disabled" => Ok(BillingProviderType::Disabled),
            "stripe" => Ok(BillingProviderType::Stripe),
            "polar" => Ok(BillingProviderType::Polar),
            _ => Err(format!("Unknown billing provider: {}", s)),
        }
    }
}

/// Normalized billing customer across all providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingCustomer {
    /// Internal database ID
    pub id: String,
    /// Organization ID this customer belongs to
    pub org_id: String,
    /// Provider type (stripe, polar, etc.)
    pub provider: BillingProviderType,
    /// External customer ID in the provider's system
    pub external_customer_id: String,
}

/// Normalized subscription status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Suspended,
    Canceled,
    Trialing,
    Incomplete,
    Unknown,
}

impl std::fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionStatus::Active => write!(f, "active"),
            SubscriptionStatus::PastDue => write!(f, "past_due"),
            SubscriptionStatus::Suspended => write!(f, "suspended"),
            SubscriptionStatus::Canceled => write!(f, "canceled"),
            SubscriptionStatus::Trialing => write!(f, "trialing"),
            SubscriptionStatus::Incomplete => write!(f, "incomplete"),
            SubscriptionStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Normalized billing events from webhooks
#[derive(Debug, Clone)]
pub enum BillingEvent {
    /// Customer was created
    CustomerCreated {
        external_customer_id: String,
        metadata: HashMap<String, String>,
    },
    /// Subscription was created or renewed
    SubscriptionCreated {
        external_customer_id: String,
        external_subscription_id: String,
        external_product_id: Option<String>,
        status: SubscriptionStatus,
        current_period_end: chrono::DateTime<chrono::Utc>,
        metadata: HashMap<String, String>,
    },
    /// Subscription was updated (plan change, etc.)
    SubscriptionUpdated {
        external_customer_id: String,
        external_subscription_id: String,
        external_product_id: Option<String>,
        status: SubscriptionStatus,
        current_period_end: chrono::DateTime<chrono::Utc>,
        metadata: HashMap<String, String>,
    },
    /// Subscription was deleted/canceled
    SubscriptionDeleted {
        external_customer_id: String,
        external_subscription_id: String,
    },
    /// Payment succeeded
    PaymentSucceeded { external_customer_id: String },
    /// Payment failed
    PaymentFailed {
        external_customer_id: String,
        attempt_count: u32,
    },
    /// Checkout completed
    CheckoutCompleted {
        external_customer_id: Option<String>,
        external_subscription_id: Option<String>,
    },
    /// Event type not handled
    Unhandled { event_type: String },
}

/// Result of creating a checkout session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResult {
    /// URL to redirect user to for checkout
    pub url: String,
    /// Session/checkout ID in the provider's system
    pub session_id: String,
}

/// Result of creating a billing portal session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalResult {
    /// URL to redirect user to for the portal
    pub url: String,
}

/// Request to create a customer
#[derive(Debug, Clone)]
pub struct CreateCustomerRequest {
    /// Organization ID
    pub org_id: String,
    /// Organization name
    pub org_name: String,
    /// Optional email
    pub email: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Request to create a checkout session
#[derive(Debug, Clone)]
pub struct CreateCheckoutRequest {
    /// External customer ID from the provider
    pub external_customer_id: String,
    /// Price/product ID in the provider's system
    pub price_id: String,
    /// URL to redirect to on success
    pub success_url: String,
    /// URL to redirect to on cancel
    pub cancel_url: String,
    /// Additional metadata to attach
    pub metadata: HashMap<String, String>,
}

/// External mapping for organization tiers
/// Stores provider-specific product/price IDs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierExternalMapping {
    /// Map of provider name to price/product ID
    #[serde(flatten)]
    pub mappings: HashMap<String, String>,
}

impl TierExternalMapping {
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    pub fn get(&self, provider: BillingProviderType) -> Option<&String> {
        self.mappings.get(&provider.to_string())
    }

    pub fn set(&mut self, provider: BillingProviderType, product_id: String) {
        self.mappings.insert(provider.to_string(), product_id);
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
