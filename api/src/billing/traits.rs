//! Billing provider trait for provider-agnostic billing operations.
//!
//! This module defines the `BillingProvider` trait which abstracts away the specifics
//! of individual billing providers (Stripe, Polar, etc.) allowing the application to
//! work with any provider through a unified interface.

#![allow(dead_code)]

use super::models::{
    BillingCustomer, BillingEvent, BillingProviderType, CheckoutResult, CreateCheckoutRequest,
    CreateCustomerRequest, PortalResult,
};
use crate::error::Result;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::HeaderMap;

/// Trait for billing provider implementations.
///
/// Each billing provider (Stripe, Polar, etc.) implements this trait to provide
/// a unified interface for billing operations.
#[async_trait]
pub trait BillingProvider: Send + Sync {
    /// Returns the provider type
    fn provider_type(&self) -> BillingProviderType;

    /// Create a customer in the billing provider's system
    async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String>;

    /// Generate a checkout link for purchasing a subscription
    async fn create_checkout_session(
        &self,
        request: CreateCheckoutRequest,
    ) -> Result<CheckoutResult>;

    /// Generate a portal link for managing existing subscription
    async fn create_portal_session(
        &self,
        external_customer_id: &str,
        return_url: &str,
    ) -> Result<PortalResult>;

    /// Verify webhook signature and parse into normalized billing event
    fn verify_webhook(&self, headers: &HeaderMap, body: &Bytes) -> Result<BillingEvent>;

    /// Get customer by external customer ID (for webhook processing)
    /// This is optional - some providers may not need this
    fn get_external_customer_id_from_event(&self, event: &BillingEvent) -> Option<String> {
        match event {
            BillingEvent::CustomerCreated {
                external_customer_id,
                ..
            } => Some(external_customer_id.clone()),
            BillingEvent::SubscriptionCreated {
                external_customer_id,
                ..
            } => Some(external_customer_id.clone()),
            BillingEvent::SubscriptionUpdated {
                external_customer_id,
                ..
            } => Some(external_customer_id.clone()),
            BillingEvent::SubscriptionDeleted {
                external_customer_id,
                ..
            } => Some(external_customer_id.clone()),
            BillingEvent::PaymentSucceeded {
                external_customer_id,
            } => Some(external_customer_id.clone()),
            BillingEvent::PaymentFailed {
                external_customer_id,
                ..
            } => Some(external_customer_id.clone()),
            BillingEvent::CheckoutCompleted {
                external_customer_id,
                ..
            } => external_customer_id.clone(),
            BillingEvent::Unhandled { .. } => None,
        }
    }
}

/// Extension trait for working with billing customers in the database
#[async_trait]
pub trait BillingCustomerStore: Send + Sync {
    /// Find a billing customer by org_id and provider
    async fn find_by_org_and_provider(
        &self,
        org_id: &str,
        provider: BillingProviderType,
    ) -> Result<Option<BillingCustomer>>;

    /// Find a billing customer by external customer ID
    async fn find_by_external_id(
        &self,
        external_customer_id: &str,
        provider: BillingProviderType,
    ) -> Result<Option<BillingCustomer>>;

    /// Create a new billing customer record
    async fn create(&self, customer: BillingCustomer) -> Result<BillingCustomer>;
}
