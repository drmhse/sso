//! Webhook handlers for billing provider events

use crate::billing::{BillingEvent, BillingProvider, BillingProviderType, SubscriptionStatus};
use crate::entities::{billing_customers, memberships, plans, services, subscriptions};
use crate::error::{AppError, Result};
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse, Json};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct WebhookState {
    pub db: DatabaseConnection,
    #[cfg(feature = "db_sqlite")]
    pub db_writer: DatabaseConnection,
    pub billing_provider: Arc<dyn BillingProvider>,
}

/// Handle billing webhooks (provider-agnostic)
/// Route: POST /webhooks/stripe or POST /webhooks/polar
pub async fn billing_webhook(
    State(state): State<WebhookState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let provider_type = state.billing_provider.provider_type();

    // Verify webhook and parse into normalized event
    let event = state.billing_provider.verify_webhook(&headers, &body)?;

    tracing::info!(
        provider = %provider_type,
        "Received billing webhook"
    );

    // Process the normalized event
    process_billing_event(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        provider_type,
        event,
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success"
        })),
    ))
}

/// Legacy Stripe webhook handler - delegates to unified handler
pub async fn stripe_webhook(
    state: State<WebhookState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    billing_webhook(state, headers, body).await
}

/// Process a normalized billing event
async fn process_billing_event(
    db: &DatabaseConnection,
    #[cfg(feature = "db_sqlite")] db_writer: &DatabaseConnection,
    provider: BillingProviderType,
    event: BillingEvent,
) -> Result<()> {
    match event {
        BillingEvent::SubscriptionCreated {
            external_customer_id,
            status,
            current_period_end,
            metadata,
            ..
        } => {
            handle_subscription_event(
                db,
                #[cfg(feature = "db_sqlite")]
                db_writer,
                provider,
                &external_customer_id,
                "created",
                status,
                current_period_end,
                metadata,
            )
            .await?;
        }
        BillingEvent::SubscriptionUpdated {
            external_customer_id,
            status,
            current_period_end,
            metadata,
            ..
        } => {
            handle_subscription_event(
                db,
                #[cfg(feature = "db_sqlite")]
                db_writer,
                provider,
                &external_customer_id,
                "updated",
                status,
                current_period_end,
                metadata,
            )
            .await?;
        }
        BillingEvent::SubscriptionDeleted {
            external_customer_id,
            ..
        } => {
            handle_subscription_deleted(
                db,
                #[cfg(feature = "db_sqlite")]
                db_writer,
                provider,
                &external_customer_id,
            )
            .await?;
        }
        BillingEvent::PaymentSucceeded {
            external_customer_id,
        } => {
            update_customer_subscription_status(
                db,
                #[cfg(feature = "db_sqlite")]
                db_writer,
                provider,
                &external_customer_id,
                "active",
            )
            .await?;
            tracing::info!(
                provider = %provider,
                customer = %external_customer_id,
                "Payment succeeded"
            );
        }
        BillingEvent::PaymentFailed {
            external_customer_id,
            attempt_count,
        } => {
            let status = if attempt_count >= 3 {
                "suspended"
            } else {
                "past_due"
            };
            update_customer_subscription_status(
                db,
                #[cfg(feature = "db_sqlite")]
                db_writer,
                provider,
                &external_customer_id,
                status,
            )
            .await?;
            tracing::warn!(
                provider = %provider,
                customer = %external_customer_id,
                attempts = attempt_count,
                status = %status,
                "Payment failed"
            );
        }
        BillingEvent::CheckoutCompleted {
            external_subscription_id,
            ..
        } => {
            if let Some(sub_id) = external_subscription_id {
                tracing::info!(
                    provider = %provider,
                    subscription = %sub_id,
                    "Checkout completed"
                );
            }
        }
        BillingEvent::CustomerCreated { .. } => {
            // Customer creation is handled by our API when needed
            tracing::debug!("Customer created event received (no-op)");
        }
        BillingEvent::Unhandled { event_type } => {
            tracing::debug!(
                provider = %provider,
                event_type = %event_type,
                "Unhandled billing event"
            );
        }
    }

    Ok(())
}

/// Handle subscription created/updated events
#[allow(clippy::too_many_arguments)]
async fn handle_subscription_event(
    pool: &DatabaseConnection,
    #[cfg(feature = "db_sqlite")] db_writer: &DatabaseConnection,
    provider: BillingProviderType,
    external_customer_id: &str,
    _event_type: &str,
    status: SubscriptionStatus,
    current_period_end: chrono::DateTime<chrono::Utc>,
    metadata: std::collections::HashMap<String, String>,
) -> Result<()> {
    use crate::error::with_retrying_transaction;

    // Extract metadata (we pass user_id, service_id, plan_id through metadata)
    let Some(user_id) = metadata.get("user_id") else {
        tracing::warn!(
            provider = %provider,
            customer = %external_customer_id,
            "Subscription event missing user_id in metadata, skipping"
        );
        return Ok(());
    };

    let Some(service_id) = metadata.get("service_id") else {
        tracing::warn!(
            provider = %provider,
            customer = %external_customer_id,
            "Subscription event missing service_id in metadata, skipping"
        );
        return Ok(());
    };

    let Some(plan_id) = metadata.get("plan_id") else {
        tracing::warn!(
            provider = %provider,
            customer = %external_customer_id,
            "Subscription event missing plan_id in metadata, skipping"
        );
        return Ok(());
    };

    let Some(org_id) = metadata.get("org_id") else {
        tracing::warn!(
            provider = %provider,
            customer = %external_customer_id,
            "Subscription event missing org_id in metadata, skipping"
        );
        return Ok(());
    };

    if !subscription_event_context_is_valid(
        pool,
        provider,
        external_customer_id,
        org_id,
        user_id,
        service_id,
        plan_id,
    )
    .await?
    {
        tracing::warn!(
            provider = %provider,
            customer = %external_customer_id,
            "Subscription event context crosses tenant or service boundaries, skipping"
        );
        return Ok(());
    }

    let status_str = status.to_string();
    let user_id = user_id.clone();
    let service_id = service_id.clone();
    let plan_id = plan_id.clone();

    with_retrying_transaction(
        pool,
        #[cfg(feature = "db_sqlite")]
        db_writer,
        "handle_subscription_event",
        |db| {
            let user_id = user_id.clone();
            let service_id = service_id.clone();
            let plan_id = plan_id.clone();
            let status_str = status_str.clone();

            Box::pin(async move {
                use sea_orm::{ActiveModelTrait, Set};

                // Check if subscription exists
                let existing = subscriptions::Entity::find()
                    .filter(subscriptions::Column::UserId.eq(user_id.as_str()))
                    .filter(subscriptions::Column::ServiceId.eq(service_id.as_str()))
                    .one(&db)
                    .await?;

                if let Some(existing_sub) = existing {
                    // Update existing subscription
                    let mut active_model: subscriptions::ActiveModel = existing_sub.into();
                    active_model.plan_id = Set(plan_id.clone());
                    active_model.status = Set(status_str);
                    active_model.current_period_end = Set(current_period_end.naive_utc());
                    active_model.update(&db).await?;
                } else {
                    // Create new subscription
                    let new_subscription = subscriptions::ActiveModel {
                        id: Set(uuid::Uuid::new_v4().to_string()),
                        user_id: Set(user_id.clone()),
                        service_id: Set(service_id.clone()),
                        plan_id: Set(plan_id.clone()),
                        status: Set(status_str),
                        current_period_end: Set(current_period_end.naive_utc()),
                        ..Default::default()
                    };

                    match new_subscription.insert(&db).await {
                        Ok(_) => {}
                        Err(e) => {
                            let error_msg = e.to_string().to_lowercase();
                            if error_msg.contains("foreign key constraint")
                                || error_msg.contains("violates")
                            {
                                tracing::warn!(
                                    user_id = %user_id,
                                    service_id = %service_id,
                                    "Subscription event references non-existent user or service, skipping"
                                );
                                return Ok(());
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }

                Ok(())
            })
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn subscription_event_context_is_valid(
    db: &DatabaseConnection,
    provider: BillingProviderType,
    external_customer_id: &str,
    org_id: &str,
    user_id: &str,
    service_id: &str,
    plan_id: &str,
) -> Result<bool> {
    let customer_matches = billing_customers::Entity::find()
        .filter(billing_customers::Column::Provider.eq(provider.to_string()))
        .filter(billing_customers::Column::ExternalCustomerId.eq(external_customer_id))
        .filter(billing_customers::Column::OrgId.eq(org_id))
        .one(db)
        .await?
        .is_some();
    if !customer_matches {
        return Ok(false);
    }

    let service_matches = services::Entity::find()
        .filter(services::Column::Id.eq(service_id))
        .filter(services::Column::OrgId.eq(org_id))
        .one(db)
        .await?
        .is_some();
    if !service_matches {
        return Ok(false);
    }

    let plan_matches = plans::Entity::find()
        .filter(plans::Column::Id.eq(plan_id))
        .filter(plans::Column::ServiceId.eq(service_id))
        .one(db)
        .await?
        .is_some();
    if !plan_matches {
        return Ok(false);
    }

    Ok(memberships::Entity::find()
        .filter(memberships::Column::OrgId.eq(org_id))
        .filter(memberships::Column::UserId.eq(user_id))
        .one(db)
        .await?
        .is_some())
}

/// Handle subscription deleted events
async fn handle_subscription_deleted(
    pool: &DatabaseConnection,
    #[cfg(feature = "db_sqlite")] db_writer: &DatabaseConnection,
    provider: BillingProviderType,
    external_customer_id: &str,
) -> Result<()> {
    // Update all subscriptions for this customer to canceled
    update_customer_subscription_status(
        pool,
        #[cfg(feature = "db_sqlite")]
        db_writer,
        provider,
        external_customer_id,
        "canceled",
    )
    .await
}

/// Find subscriptions by billing customer
async fn find_subscriptions_by_customer(
    pool: &DatabaseConnection,
    provider: BillingProviderType,
    external_customer_id: &str,
) -> Result<Vec<subscriptions::Model>> {
    // Find the organization by billing customer ID
    let billing_customer = billing_customers::Entity::find()
        .filter(billing_customers::Column::Provider.eq(provider.to_string()))
        .filter(billing_customers::Column::ExternalCustomerId.eq(external_customer_id))
        .one(pool)
        .await?
        .ok_or_else(|| {
            AppError::Billing(format!(
                "No organization found for {} customer: {}",
                provider, external_customer_id
            ))
        })?;

    use sea_orm::{JoinType, QuerySelect, RelationTrait};

    let org_subscriptions = subscriptions::Entity::find()
        .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
        .filter(services::Column::OrgId.eq(&billing_customer.org_id))
        .all(pool)
        .await?;

    Ok(org_subscriptions)
}

/// Update subscription status for all subscriptions of a customer
async fn update_customer_subscription_status(
    pool: &DatabaseConnection,
    #[cfg(feature = "db_sqlite")] db_writer: &DatabaseConnection,
    provider: BillingProviderType,
    external_customer_id: &str,
    status: &str,
) -> Result<()> {
    let found_subscriptions =
        match find_subscriptions_by_customer(pool, provider, external_customer_id).await {
            Ok(subs) => subs,
            Err(e) => {
                tracing::warn!(
                    provider = %provider,
                    customer = %external_customer_id,
                    error = %e,
                    "Could not find subscriptions for customer, may be test data"
                );
                return Ok(());
            }
        };

    if found_subscriptions.is_empty() {
        tracing::warn!(
            provider = %provider,
            customer = %external_customer_id,
            "No subscriptions found for customer"
        );
        return Ok(());
    }

    use crate::error::with_retrying_transaction;
    use sea_orm::Set;

    let status = status.to_string();
    let external_customer_id = external_customer_id.to_string();
    let subscription_ids = found_subscriptions
        .iter()
        .map(|subscription| subscription.id.clone())
        .collect::<Vec<_>>();

    with_retrying_transaction(
        pool,
        #[cfg(feature = "db_sqlite")]
        db_writer,
        "update_customer_subscription_status",
        |db| {
            let status = status.clone();
            let subscription_ids = subscription_ids.clone();
            Box::pin(async move {
                subscriptions::Entity::update_many()
                    .filter(subscriptions::Column::Id.is_in(subscription_ids))
                    .set(subscriptions::ActiveModel {
                        status: Set(status),
                        ..Default::default()
                    })
                    .exec(&db)
                    .await
                    .map_err(AppError::SeaOrmDatabase)?;
                Ok(())
            })
        },
    )
    .await?;

    tracing::info!(
        provider = %provider,
        customer = %external_customer_id,
        count = found_subscriptions.len(),
        status = %status,
        "Updated subscription status"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::billing_customers;
    use crate::store::{
        organizations::OrganizationStore, plans::PlanStore, services::ServiceStore,
        users::UserStore, DB,
    };
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn subscription_webhook_rejects_cross_tenant_metadata_and_preserves_state() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner_a = UserStore::create(DB::Conn(&db), "webhook-a@example.com", None, false)
            .await
            .expect("create owner A");
        let owner_b = UserStore::create(DB::Conn(&db), "webhook-b@example.com", None, false)
            .await
            .expect("create owner B");
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "webhook-org-a",
            "Webhook Org A",
            &owner_a.id,
            None,
        )
        .await
        .expect("create org A");
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "webhook-org-b",
            "Webhook Org B",
            &owner_b.id,
            None,
        )
        .await
        .expect("create org B");
        let service_a = ServiceStore::create(
            DB::Conn(&db),
            &org_a.id,
            "webhook-service-a",
            "Webhook Service A",
            "web",
            "webhook-client-a",
        )
        .await
        .expect("create service A");
        let service_b = ServiceStore::create(
            DB::Conn(&db),
            &org_b.id,
            "webhook-service-b",
            "Webhook Service B",
            "web",
            "webhook-client-b",
        )
        .await
        .expect("create service B");
        PlanStore::create(
            DB::Conn(&db),
            "webhook-plan-a",
            &service_a.id,
            "Plan A",
            None,
            100,
            "USD",
            "[]",
            Some("price-a"),
            false,
            Utc::now().naive_utc(),
        )
        .await
        .expect("create plan A");
        PlanStore::create(
            DB::Conn(&db),
            "webhook-plan-b",
            &service_b.id,
            "Plan B",
            None,
            200,
            "USD",
            "[]",
            Some("price-b"),
            false,
            Utc::now().naive_utc(),
        )
        .await
        .expect("create plan B");
        billing_customers::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_a.id.clone()),
            provider: Set("stripe".to_string()),
            external_customer_id: Set("customer-a".to_string()),
            created_at: Set(Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("create org A billing customer");
        let target = subscriptions::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(owner_b.id.clone()),
            service_id: Set(service_b.id.clone()),
            plan_id: Set("webhook-plan-b".to_string()),
            status: Set("active".to_string()),
            current_period_end: Set((Utc::now() + Duration::days(30)).naive_utc()),
            created_at: Set(Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("create org B subscription");
        let before = target.clone();
        let metadata = HashMap::from([
            ("org_id".to_string(), org_b.id.clone()),
            ("user_id".to_string(), owner_b.id.clone()),
            ("service_id".to_string(), service_b.id.clone()),
            ("plan_id".to_string(), "webhook-plan-b".to_string()),
        ]);

        handle_subscription_event(
            &db,
            #[cfg(feature = "db_sqlite")]
            &db,
            BillingProviderType::Stripe,
            "customer-a",
            "updated",
            SubscriptionStatus::Canceled,
            Utc::now() + Duration::days(1),
            metadata,
        )
        .await
        .expect("cross-tenant webhook is ignored");

        let unchanged = subscriptions::Entity::find_by_id(&target.id)
            .one(&db)
            .await
            .expect("reload subscription")
            .expect("target subscription remains");
        assert_eq!(unchanged.status, before.status);
        assert_eq!(unchanged.plan_id, before.plan_id);
        assert_eq!(unchanged.current_period_end, before.current_period_end);
        assert_eq!(
            subscriptions::Entity::find()
                .filter(subscriptions::Column::ServiceId.eq(&service_a.id))
                .all(&db)
                .await
                .expect("check org A subscriptions")
                .len(),
            0
        );
    }
}
