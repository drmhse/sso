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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_operation_reports_billing_as_disabled() {
        let provider = DisabledBillingProvider::new();
        assert_eq!(provider.provider_type(), BillingProviderType::Disabled);

        let results = (
            provider
                .create_customer(CreateCustomerRequest {
                    org_id: "org".to_string(),
                    org_name: "Org".to_string(),
                    email: Some("billing@example.test".to_string()),
                    metadata: Default::default(),
                })
                .await
                .err(),
            provider
                .create_checkout_session(CreateCheckoutRequest {
                    external_customer_id: "cus_1".to_string(),
                    price_id: "price_1".to_string(),
                    success_url: "https://x".to_string(),
                    cancel_url: "https://x".to_string(),
                    metadata: Default::default(),
                })
                .await
                .err(),
            provider
                .create_portal_session("cus_1", "https://x")
                .await
                .err(),
            provider
                .verify_webhook(&HeaderMap::new(), &Bytes::from_static(b"{}"))
                .err(),
        );

        match results {
            (
                Some(AppError::Billing(message)),
                Some(AppError::Billing(_)),
                Some(AppError::Billing(_)),
                Some(AppError::Billing(_)),
            ) => assert!(message.contains("Billing is disabled")),
            other => panic!("expected uniform billing-disabled errors, got {other:?}"),
        }
    }
}
