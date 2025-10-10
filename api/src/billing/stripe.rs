use crate::db::models::{Organization, StripeCustomer};
use crate::error::{AppError, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use stripe::{
    CheckoutSession, CheckoutSessionMode, Client, CreateCheckoutSession,
    CreateCheckoutSessionLineItems, CreateCustomer, Customer, Event, EventObject, EventType,
    Webhook,
};
use uuid::Uuid;

pub struct StripeService {
    #[allow(dead_code)]
    client: Client,
    webhook_secret: String,
}

impl StripeService {
    pub fn new(api_key: String, webhook_secret: String) -> Self {
        let client = Client::new(api_key);
        Self {
            client,
            webhook_secret,
        }
    }

    #[allow(dead_code)]
    pub async fn create_customer_for_org(
        &self,
        pool: &SqlitePool,
        org: &Organization,
    ) -> Result<StripeCustomer> {
        // Check if customer already exists
        if let Some(existing) = self.get_customer_by_org_id(pool, &org.id).await? {
            return Ok(existing);
        }

        // Create Stripe customer
        let mut params = CreateCustomer::new();
        params.name = Some(&org.name);
        params.metadata = Some(
            [("org_id".to_string(), org.id.clone())]
                .iter()
                .cloned()
                .collect(),
        );

        let customer = Customer::create(&self.client, params)
            .await
            .map_err(|e| AppError::Stripe(e.to_string()))?;

        // Store in database
        let id = Uuid::new_v4().to_string();
        let stripe_customer = sqlx::query_as::<_, StripeCustomer>(
            r#"
            INSERT INTO stripe_customers (id, org_id, stripe_customer_id)
            VALUES (?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&org.id)
        .bind(customer.id.to_string())
        .fetch_one(pool)
        .await?;

        Ok(stripe_customer)
    }

    #[allow(dead_code)]
    pub async fn get_customer_by_org_id(
        &self,
        pool: &SqlitePool,
        org_id: &str,
    ) -> Result<Option<StripeCustomer>> {
        let customer = sqlx::query_as::<_, StripeCustomer>(
            r#"
            SELECT * FROM stripe_customers WHERE org_id = ?
            "#,
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await?;

        Ok(customer)
    }

    #[allow(dead_code)]
    pub async fn create_checkout_session(
        &self,
        customer_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
        metadata: Vec<(String, String)>,
    ) -> Result<CheckoutSession> {
        let mut params = CreateCheckoutSession::new();
        params.customer = Some(
            customer_id
                .parse()
                .map_err(|_| AppError::Stripe("Invalid customer ID".to_string()))?,
        );
        params.mode = Some(CheckoutSessionMode::Subscription);
        params.success_url = Some(success_url);
        params.cancel_url = Some(cancel_url);
        params.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(price_id.to_string()),
            quantity: Some(1),
            ..Default::default()
        }]);
        params.metadata = Some(metadata.into_iter().collect());

        let session = CheckoutSession::create(&self.client, params)
            .await
            .map_err(|e| AppError::Stripe(e.to_string()))?;

        Ok(session)
    }

    /// Verify webhook signature and parse event
    pub fn verify_webhook(&self, payload: &str, signature: &str) -> Result<Event> {
        Webhook::construct_event(payload, signature, &self.webhook_secret)
            .map_err(|e| AppError::Stripe(format!("Webhook verification failed: {}", e)))
    }

    /// Handle subscription created/updated event
    pub async fn handle_subscription_event(
        pool: &SqlitePool,
        subscription: &stripe::Subscription,
    ) -> Result<()> {
        // Extract metadata
        let metadata = &subscription.metadata;

        let user_id = metadata
            .get("user_id")
            .ok_or_else(|| AppError::Stripe("Missing user_id in metadata".to_string()))?;

        let service_id = metadata
            .get("service_id")
            .ok_or_else(|| AppError::Stripe("Missing service_id in metadata".to_string()))?;

        let plan_id = metadata
            .get("plan_id")
            .ok_or_else(|| AppError::Stripe("Missing plan_id in metadata".to_string()))?;

        let status = subscription.status.to_string();
        let current_period_end =
            chrono::DateTime::from_timestamp(subscription.current_period_end, 0)
                .unwrap_or_else(|| Utc::now());

        // Upsert subscription
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO subscriptions (id, user_id, service_id, plan_id, status, current_period_end)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, service_id)
            DO UPDATE SET plan_id = ?, status = ?, current_period_end = ?
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(service_id)
        .bind(plan_id)
        .bind(&status)
        .bind(current_period_end)
        .bind(plan_id)
        .bind(&status)
        .bind(current_period_end)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Handle checkout session completed event
    pub async fn handle_checkout_completed(
        _pool: &SqlitePool,
        session: &CheckoutSession,
    ) -> Result<()> {
        // Extract subscription from session
        if let Some(ref subscription_id) = session.subscription {
            tracing::info!("Checkout completed for subscription: {:?}", subscription_id);
            // The subscription webhook will handle the actual creation
        }

        Ok(())
    }

    /// Process webhook event
    pub async fn process_webhook_event(pool: &SqlitePool, event: Event) -> Result<()> {
        match event.type_ {
            EventType::CheckoutSessionCompleted => {
                if let EventObject::CheckoutSession(session) = event.data.object {
                    Self::handle_checkout_completed(pool, &session).await?;
                }
            }
            EventType::CustomerSubscriptionCreated | EventType::CustomerSubscriptionUpdated => {
                if let EventObject::Subscription(subscription) = event.data.object {
                    Self::handle_subscription_event(pool, &subscription).await?;
                }
            }
            EventType::CustomerSubscriptionDeleted => {
                if let EventObject::Subscription(subscription) = event.data.object {
                    // Mark subscription as cancelled
                    let metadata = &subscription.metadata;
                    if let (Some(user_id), Some(service_id)) =
                        (metadata.get("user_id"), metadata.get("service_id"))
                    {
                        sqlx::query(
                            r#"
                            UPDATE subscriptions
                            SET status = 'cancelled'
                            WHERE user_id = ? AND service_id = ?
                            "#,
                        )
                        .bind(user_id)
                        .bind(service_id)
                        .execute(pool)
                        .await?;
                    }
                }
            }
            _ => {
                tracing::debug!("Unhandled event type: {:?}", event.type_);
            }
        }

        Ok(())
    }
}
