use crate::billing::{
    BillingEvent, BillingProvider, BillingProviderType, CheckoutResult, CreateCheckoutRequest,
    CreateCustomerRequest, PortalResult,
};
use crate::error::{AppError, Result};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::HeaderMap;

pub struct DisabledBillingProvider;

impl DisabledBillingProvider {
    pub fn new() -> Self {
        Self
    }

    fn unavailable<T>() -> Result<T> {
        Err(AppError::Billing(
            "Billing is disabled for this AuthOS instance.".to_string(),
        ))
    }
}

#[async_trait]
impl BillingProvider for DisabledBillingProvider {
    fn provider_type(&self) -> BillingProviderType {
        BillingProviderType::Disabled
    }

    async fn create_customer(&self, _request: CreateCustomerRequest) -> Result<String> {
        Self::unavailable()
    }

    async fn create_checkout_session(
        &self,
        _request: CreateCheckoutRequest,
    ) -> Result<CheckoutResult> {
        Self::unavailable()
    }

    async fn create_portal_session(
        &self,
        _external_customer_id: &str,
        _return_url: &str,
    ) -> Result<PortalResult> {
        Self::unavailable()
    }

    fn verify_webhook(&self, _headers: &HeaderMap, _body: &Bytes) -> Result<BillingEvent> {
        Self::unavailable()
    }
}
