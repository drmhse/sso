use crate::db::models::WebhookDeliveryWithWebhook;
use crate::entities::prelude::WebhookDeliveries;
use crate::entities::webhook_deliveries;
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, JoinType, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Set,
};
use uuid::Uuid;

pub struct WebhookDeliveryStore;

#[derive(Debug, Clone)]
pub struct AuthorizedWebhookDelivery {
    pub delivery: webhook_deliveries::Model,
    pub webhook: crate::entities::webhooks::Model,
}

impl WebhookDeliveryStore {
    /// Load one exact open delivery together with its live authorization
    /// parents. This is the worker boundary: payload IDs must agree, the
    /// webhook must still be enabled, and its organization must still be
    /// active immediately before outbound I/O.
    pub async fn find_authorized_open_delivery(
        db: DB<'_>,
        delivery_id: &str,
        webhook_id: &str,
    ) -> Result<Option<AuthorizedWebhookDelivery>> {
        use crate::entities::{organizations, webhooks};

        let row = WebhookDeliveries::find()
            .find_also_related(webhooks::Entity)
            .join(JoinType::InnerJoin, webhooks::Relation::Organizations.def())
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .filter(webhook_deliveries::Column::WebhookId.eq(webhook_id))
            .filter(webhook_deliveries::Column::Delivered.eq(false))
            .filter(
                Expr::col((
                    webhook_deliveries::Entity,
                    webhook_deliveries::Column::AttemptCount,
                ))
                .lt(Expr::col((
                    webhook_deliveries::Entity,
                    webhook_deliveries::Column::MaxAttempts,
                ))),
            )
            .filter(webhooks::Column::IsActive.eq(true))
            .filter(organizations::Column::Status.eq("active"))
            .one(&db)
            .await?;

        Ok(row.and_then(|(delivery, webhook)| {
            webhook.map(|webhook| AuthorizedWebhookDelivery { delivery, webhook })
        }))
    }

    pub async fn mark_as_successful_with_response_for_webhook(
        db: DB<'_>,
        delivery_id: &str,
        webhook_id: &str,
        status_code: i32,
        response_body: Option<String>,
    ) -> Result<bool> {
        let result = WebhookDeliveries::update_many()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .filter(webhook_deliveries::Column::WebhookId.eq(webhook_id))
            .filter(webhook_deliveries::Column::Delivered.eq(false))
            .col_expr(webhook_deliveries::Column::Delivered, Expr::value(true))
            .col_expr(
                webhook_deliveries::Column::NextRetryAt,
                Expr::value(None::<chrono::NaiveDateTime>),
            )
            .col_expr(
                webhook_deliveries::Column::DeliveryError,
                Expr::value(None::<String>),
            )
            .col_expr(
                webhook_deliveries::Column::ResponseStatusCode,
                Expr::value(Some(status_code)),
            )
            .col_expr(
                webhook_deliveries::Column::ResponseBody,
                Expr::value(response_body),
            )
            .col_expr(
                webhook_deliveries::Column::UpdatedAt,
                Expr::value(Utc::now().naive_utc()),
            )
            .exec(&db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn schedule_retry_for_webhook(
        db: DB<'_>,
        delivery_id: &str,
        webhook_id: &str,
        next_retry_at: chrono::NaiveDateTime,
        error: Option<String>,
        response: Option<(i32, Option<String>)>,
    ) -> Result<bool> {
        let mut update = WebhookDeliveries::update_many()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .filter(webhook_deliveries::Column::WebhookId.eq(webhook_id))
            .filter(webhook_deliveries::Column::Delivered.eq(false))
            .filter(
                Expr::col(webhook_deliveries::Column::AttemptCount)
                    .lt(Expr::col(webhook_deliveries::Column::MaxAttempts)),
            )
            .col_expr(
                webhook_deliveries::Column::AttemptCount,
                Expr::col(webhook_deliveries::Column::AttemptCount).add(1),
            )
            .col_expr(
                webhook_deliveries::Column::NextRetryAt,
                Expr::value(Some(next_retry_at)),
            )
            .col_expr(
                webhook_deliveries::Column::DeliveryError,
                Expr::value(error.or_else(|| Some("Retry scheduled".to_string()))),
            )
            .col_expr(
                webhook_deliveries::Column::UpdatedAt,
                Expr::value(Utc::now().naive_utc()),
            );
        if let Some((status_code, body)) = response {
            update = update
                .col_expr(
                    webhook_deliveries::Column::ResponseStatusCode,
                    Expr::value(Some(status_code)),
                )
                .col_expr(webhook_deliveries::Column::ResponseBody, Expr::value(body));
        }
        let result = update.exec(&db).await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn mark_as_failed_permanently_for_webhook(
        db: DB<'_>,
        delivery_id: &str,
        webhook_id: &str,
        error: Option<String>,
        response: Option<(i32, Option<String>)>,
    ) -> Result<bool> {
        let mut update = WebhookDeliveries::update_many()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .filter(webhook_deliveries::Column::WebhookId.eq(webhook_id))
            .filter(webhook_deliveries::Column::Delivered.eq(false))
            .col_expr(
                webhook_deliveries::Column::AttemptCount,
                Expr::col(webhook_deliveries::Column::MaxAttempts).into(),
            )
            .col_expr(
                webhook_deliveries::Column::NextRetryAt,
                Expr::value(None::<chrono::NaiveDateTime>),
            )
            .col_expr(
                webhook_deliveries::Column::DeliveryError,
                Expr::value(error.or_else(|| Some("Max retries exceeded".to_string()))),
            )
            .col_expr(
                webhook_deliveries::Column::UpdatedAt,
                Expr::value(Utc::now().naive_utc()),
            );
        if let Some((status_code, body)) = response {
            update = update
                .col_expr(
                    webhook_deliveries::Column::ResponseStatusCode,
                    Expr::value(Some(status_code)),
                )
                .col_expr(webhook_deliveries::Column::ResponseBody, Expr::value(body));
        }
        let result = update.exec(&db).await?;
        Ok(result.rows_affected == 1)
    }

    /// Get pending webhook deliveries that are ready to be processed
    pub async fn get_pending_deliveries(
        db: DB<'_>,
        limit: u64,
    ) -> Result<Vec<webhook_deliveries::Model>> {
        use crate::entities::{organizations, webhooks};
        use sea_orm::Condition;

        let now = Utc::now().naive_utc();

        let deliveries = WebhookDeliveries::find()
            .join(
                JoinType::InnerJoin,
                webhook_deliveries::Relation::Webhooks.def(),
            )
            .join(JoinType::InnerJoin, webhooks::Relation::Organizations.def())
            .filter(webhook_deliveries::Column::Delivered.eq(false))
            .filter(
                Condition::any()
                    .add(webhook_deliveries::Column::NextRetryAt.is_null())
                    .add(webhook_deliveries::Column::NextRetryAt.lte(now)),
            )
            .filter(
                Expr::col((
                    webhook_deliveries::Entity,
                    webhook_deliveries::Column::AttemptCount,
                ))
                .lt(Expr::col((
                    webhook_deliveries::Entity,
                    webhook_deliveries::Column::MaxAttempts,
                ))),
            )
            .filter(webhooks::Column::IsActive.eq(true))
            .filter(organizations::Column::Status.eq("active"))
            .order_by_asc(webhook_deliveries::Column::CreatedAt)
            .limit(limit)
            .all(&db)
            .await?;

        Ok(deliveries)
    }

    /// Create a new webhook delivery record
    pub async fn create_delivery(
        db: DB<'_>,
        webhook_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
        max_attempts: i32,
    ) -> Result<String> {
        let delivery_id = Uuid::new_v4().to_string();
        let payload_json = serde_json::to_string(payload).unwrap();
        let now = Utc::now().naive_utc();

        let new_delivery = webhook_deliveries::ActiveModel {
            id: Set(delivery_id.clone()),
            webhook_id: Set(webhook_id.to_string()),
            event_type: Set(event_type.to_string()),
            payload: Set(payload_json),
            response_status_code: Set(None),
            response_body: Set(None),
            attempt_count: Set(0),
            max_attempts: Set(max_attempts),
            next_retry_at: Set(Some(now)), // Try immediately
            delivered: Set(false),
            delivery_error: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };

        new_delivery.insert(&db).await?;

        Ok(delivery_id)
    }

    /// Mark delivery as successful
    pub async fn mark_as_successful(db: DB<'_>, delivery_id: &str) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Find the delivery
        let delivery = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Delivery not found".to_string()))?;

        // Update it
        let mut active_delivery = delivery.into_active_model();
        active_delivery.delivered = Set(true);
        active_delivery.next_retry_at = Set(None);
        active_delivery.delivery_error = Set(None);
        active_delivery.updated_at = Set(now);

        active_delivery.update(&db).await?;

        Ok(())
    }

    /// Mark delivery as successful with response details
    pub async fn mark_as_successful_with_response(
        db: DB<'_>,
        delivery_id: &str,
        status_code: i32,
        response_body: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Find the delivery
        let delivery = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Delivery not found".to_string()))?;

        // Update it
        let mut active_delivery = delivery.into_active_model();
        active_delivery.delivered = Set(true);
        active_delivery.next_retry_at = Set(None);
        active_delivery.delivery_error = Set(None);
        active_delivery.response_status_code = Set(Some(status_code));
        active_delivery.response_body = Set(response_body);
        active_delivery.updated_at = Set(now);

        active_delivery.update(&db).await?;

        Ok(())
    }

    /// Schedule retry with exponential backoff
    pub async fn schedule_retry(
        db: DB<'_>,
        delivery_id: &str,
        next_retry_at: chrono::NaiveDateTime,
        error: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Find the delivery
        let delivery = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Delivery not found".to_string()))?;

        // Update it
        let mut active_delivery = delivery.into_active_model();
        active_delivery.attempt_count = Set(active_delivery.attempt_count.as_ref() + 1);
        active_delivery.next_retry_at = Set(Some(next_retry_at));
        active_delivery.delivery_error = Set(error.or_else(|| Some("Retry scheduled".to_string())));
        active_delivery.updated_at = Set(now);

        active_delivery.update(&db).await?;

        Ok(())
    }

    /// Schedule retry with exponential backoff and response details
    pub async fn schedule_retry_with_response(
        db: DB<'_>,
        delivery_id: &str,
        next_retry_at: chrono::NaiveDateTime,
        error: Option<String>,
        status_code: i32,
        response_body: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Find the delivery
        let delivery = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Delivery not found".to_string()))?;

        // Update it
        let mut active_delivery = delivery.into_active_model();
        active_delivery.attempt_count = Set(active_delivery.attempt_count.as_ref() + 1);
        active_delivery.next_retry_at = Set(Some(next_retry_at));
        active_delivery.delivery_error = Set(error.or_else(|| Some("Retry scheduled".to_string())));
        active_delivery.response_status_code = Set(Some(status_code));
        active_delivery.response_body = Set(response_body);
        active_delivery.updated_at = Set(now);

        active_delivery.update(&db).await?;

        Ok(())
    }

    /// Mark delivery as permanently failed
    pub async fn mark_as_failed_permanently(
        db: DB<'_>,
        delivery_id: &str,
        error: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Find the delivery
        let delivery = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Delivery not found".to_string()))?;

        // Update it
        let mut active_delivery = delivery.into_active_model();
        active_delivery.delivered = Set(false);
        active_delivery.next_retry_at = Set(None);
        active_delivery.delivery_error =
            Set(error.or_else(|| Some("Max retries exceeded".to_string())));
        active_delivery.updated_at = Set(now);

        active_delivery.update(&db).await?;

        Ok(())
    }

    /// Mark delivery as permanently failed with response details
    pub async fn mark_as_failed_permanently_with_response(
        db: DB<'_>,
        delivery_id: &str,
        error: Option<String>,
        status_code: i32,
        response_body: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Find the delivery
        let delivery = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Id.eq(delivery_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Delivery not found".to_string()))?;

        // Update it
        let mut active_delivery = delivery.into_active_model();
        active_delivery.delivered = Set(false);
        active_delivery.next_retry_at = Set(None);
        active_delivery.delivery_error =
            Set(error.or_else(|| Some("Max retries exceeded".to_string())));
        active_delivery.response_status_code = Set(Some(status_code));
        active_delivery.response_body = Set(response_body);
        active_delivery.updated_at = Set(now);

        active_delivery.update(&db).await?;

        Ok(())
    }

    /// Delete old successful webhook deliveries
    pub async fn delete_old_successful_deliveries(db: DB<'_>, cutoff_date: &str) -> Result<u64> {
        use chrono::NaiveDateTime;

        // Parse the cutoff date string to NaiveDateTime
        let cutoff_datetime = NaiveDateTime::parse_from_str(cutoff_date, "%Y-%m-%d %H:%M:%S")
            .or_else(|_| {
                NaiveDateTime::parse_from_str(
                    &format!("{} 00:00:00", cutoff_date),
                    "%Y-%m-%d %H:%M:%S",
                )
            })
            .map_err(|e| {
                crate::error::AppError::BadRequest(format!("Invalid date format: {}", e))
            })?;

        let result = WebhookDeliveries::delete_many()
            .filter(webhook_deliveries::Column::Delivered.eq(true))
            .filter(webhook_deliveries::Column::CreatedAt.lt(cutoff_datetime))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Get webhook deliveries with optional filters and pagination
    pub async fn get_deliveries_with_filters(
        db: DB<'_>,
        webhook_id: &str,
        event_type: Option<&str>,
        delivered: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookDeliveryWithWebhook>> {
        use crate::entities::webhooks;
        use sea_orm::{JoinType, QueryOrder, QuerySelect, RelationTrait};

        let mut query = WebhookDeliveries::find()
            .join(
                JoinType::InnerJoin,
                webhook_deliveries::Relation::Webhooks.def(),
            )
            .filter(webhook_deliveries::Column::WebhookId.eq(webhook_id));

        if let Some(et) = event_type {
            query = query.filter(webhook_deliveries::Column::EventType.eq(et));
        }

        if let Some(d) = delivered {
            query = query.filter(webhook_deliveries::Column::Delivered.eq(d));
        }

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 100);
        let deliveries = query
            .select_only()
            .column(webhook_deliveries::Column::Id)
            .column(webhook_deliveries::Column::WebhookId)
            .column_as(webhooks::Column::Name, "webhook_name")
            .column_as(webhooks::Column::Url, "webhook_url")
            .column(webhook_deliveries::Column::EventType)
            .column(webhook_deliveries::Column::Payload)
            .column(webhook_deliveries::Column::ResponseStatusCode)
            .column(webhook_deliveries::Column::ResponseBody)
            .column(webhook_deliveries::Column::AttemptCount)
            .column(webhook_deliveries::Column::MaxAttempts)
            .column(webhook_deliveries::Column::NextRetryAt)
            .column(webhook_deliveries::Column::Delivered)
            .column(webhook_deliveries::Column::DeliveryError)
            .column_as(
                Expr::col((
                    webhook_deliveries::Entity,
                    webhook_deliveries::Column::CreatedAt,
                )),
                "created_at",
            )
            .column_as(
                Expr::col((
                    webhook_deliveries::Entity,
                    webhook_deliveries::Column::UpdatedAt,
                )),
                "updated_at",
            )
            .order_by_desc(Expr::col((
                webhook_deliveries::Entity,
                webhook_deliveries::Column::CreatedAt,
            )))
            .limit(limit)
            .offset(offset)
            .into_model::<WebhookDeliveryWithWebhook>()
            .all(&db)
            .await?;

        Ok(deliveries)
    }

    /// Count webhook deliveries with optional filters
    pub async fn count_deliveries_with_filters(
        db: DB<'_>,
        webhook_id: &str,
        event_type: Option<&str>,
        delivered: Option<bool>,
    ) -> Result<i64> {
        use sea_orm::PaginatorTrait;

        let mut query =
            WebhookDeliveries::find().filter(webhook_deliveries::Column::WebhookId.eq(webhook_id));

        if let Some(event_type_val) = event_type {
            query = query.filter(webhook_deliveries::Column::EventType.eq(event_type_val));
        }

        if let Some(delivered_val) = delivered {
            query = query.filter(webhook_deliveries::Column::Delivered.eq(delivered_val));
        }

        let total = query.count(&db).await? as i64;

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
        webhooks::WebhookStore,
        DB,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database};
    use serde_json::json;

    async fn setup_db() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    #[tokio::test]
    async fn pending_delivery_polling_reauthorizes_active_parent_and_honors_limit() {
        let db = setup_db().await;
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "webhook-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "webhook-test",
            "Webhook Test",
            &owner.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let now = Utc::now().naive_utc();

        WebhookStore::create(
            DB::Conn(&db),
            "active-webhook",
            &org.id,
            "Active",
            "https://example.com/active",
            vec![1, 2, 3],
            "test-key",
            r#"["user.created"]"#,
            true,
            now,
            now,
        )
        .await
        .expect("create active webhook");
        WebhookStore::create(
            DB::Conn(&db),
            "inactive-webhook",
            &org.id,
            "Inactive",
            "https://example.com/inactive",
            vec![1, 2, 3],
            "test-key",
            r#"["user.created"]"#,
            false,
            now,
            now,
        )
        .await
        .expect("create inactive webhook");

        let eligible_id = WebhookDeliveryStore::create_delivery(
            DB::Conn(&db),
            "active-webhook",
            "user.created",
            &serde_json::json!({ "id": "eligible" }),
            3,
        )
        .await
        .expect("create eligible delivery");
        let unrelated_id = WebhookDeliveryStore::create_delivery(
            DB::Conn(&db),
            "active-webhook",
            "user.created",
            &serde_json::json!({ "id": "unrelated" }),
            3,
        )
        .await
        .expect("create unrelated delivery");
        WebhookDeliveryStore::create_delivery(
            DB::Conn(&db),
            "inactive-webhook",
            "user.created",
            &serde_json::json!({ "id": "inactive" }),
            3,
        )
        .await
        .expect("create inactive delivery");

        let exhausted = webhook_deliveries::ActiveModel {
            id: Set("exhausted-delivery".to_string()),
            webhook_id: Set("active-webhook".to_string()),
            event_type: Set("user.created".to_string()),
            payload: Set(r#"{"id":"exhausted"}"#.to_string()),
            response_status_code: Set(None),
            response_body: Set(None),
            attempt_count: Set(3),
            max_attempts: Set(3),
            next_retry_at: Set(Some(now)),
            delivered: Set(false),
            delivery_error: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        exhausted
            .insert(&db)
            .await
            .expect("create exhausted delivery");

        let deliveries = WebhookDeliveryStore::get_pending_deliveries(DB::Conn(&db), 10)
            .await
            .expect("poll pending deliveries");
        assert_eq!(deliveries.len(), 2);
        assert!(deliveries.iter().any(|delivery| delivery.id == eligible_id));
        assert!(deliveries
            .iter()
            .any(|delivery| delivery.id == unrelated_id));

        let authorized = WebhookDeliveryStore::find_authorized_open_delivery(
            DB::Conn(&db),
            &unrelated_id,
            "active-webhook",
        )
        .await
        .expect("load exact authorized delivery")
        .expect("unrelated delivery is independently addressable");
        assert_eq!(authorized.delivery.id, unrelated_id);
        assert_eq!(authorized.webhook.id, "active-webhook");
        assert!(WebhookDeliveryStore::find_authorized_open_delivery(
            DB::Conn(&db),
            &unrelated_id,
            "inactive-webhook",
        )
        .await
        .expect("reject mismatched webhook identity")
        .is_none());

        WebhookDeliveryStore::schedule_retry_for_webhook(
            DB::Conn(&db),
            &unrelated_id,
            "active-webhook",
            now + chrono::Duration::minutes(1),
            Some("targeted retry".to_string()),
            None,
        )
        .await
        .expect("schedule exact target retry");
        let unrelated = WebhookDeliveries::find_by_id(&unrelated_id)
            .one(&db)
            .await
            .expect("load unrelated")
            .expect("unrelated exists");
        let eligible = WebhookDeliveries::find_by_id(&eligible_id)
            .one(&db)
            .await
            .expect("load eligible")
            .expect("eligible exists");
        assert_eq!(unrelated.attempt_count, 1);
        assert_eq!(eligible.attempt_count, 0);

        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend org");
        assert!(
            WebhookDeliveryStore::get_pending_deliveries(DB::Conn(&db), 10)
                .await
                .expect("poll suspended organization")
                .is_empty()
        );
        assert!(WebhookDeliveryStore::find_authorized_open_delivery(
            DB::Conn(&db),
            &eligible_id,
            "active-webhook",
        )
        .await
        .expect("reauthorize after enqueue")
        .is_none());

        assert!(
            WebhookDeliveryStore::mark_as_failed_permanently_for_webhook(
                DB::Conn(&db),
                &eligible_id,
                "active-webhook",
                Some("parent suspended".to_string()),
                None,
            )
            .await
            .expect("fail exact suspended delivery")
        );
        let failed = WebhookDeliveries::find_by_id(&eligible_id)
            .one(&db)
            .await
            .expect("load failed target")
            .expect("failed target exists");
        let untouched = WebhookDeliveries::find_by_id(&unrelated_id)
            .one(&db)
            .await
            .expect("load unrelated after target failure")
            .expect("unrelated remains");
        assert_eq!(failed.delivery_error.as_deref(), Some("parent suspended"));
        assert_eq!(untouched.delivery_error.as_deref(), Some("targeted retry"));

        let limited = WebhookDeliveryStore::get_pending_deliveries(DB::Conn(&db), 0)
            .await
            .expect("poll with zero limit");
        assert!(limited.is_empty());
    }
    #[tokio::test]
    async fn deliveries_move_through_success_retry_and_failure_states() {
        let db = setup_db().await;
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "lifecycle-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "delivery-lifecycle",
            "Delivery Lifecycle",
            &owner.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let now = Utc::now().naive_utc();
        WebhookStore::create(
            DB::Conn(&db),
            "lifecycle-webhook",
            &org.id,
            "hooked",
            "https://hooks.example.test/ingest",
            b"encrypted-secret".to_vec(),
            "key-1",
            r#"["user.signup.success"]"#,
            true,
            now,
            now,
        )
        .await
        .expect("create webhook");

        async fn make_delivery(db: &sea_orm::DatabaseConnection, name: &str) -> String {
            WebhookDeliveryStore::create_delivery(
                DB::Conn(db),
                "lifecycle-webhook",
                "user.signup.success",
                &json!({ "name": name }),
                3,
            )
            .await
            .expect("create delivery")
        }
        let ok_id = make_delivery(&db, "ok").await;
        let retry_id = make_delivery(&db, "retry").await;
        let dead_id = make_delivery(&db, "dead").await;

        WebhookDeliveryStore::mark_as_successful_with_response_for_webhook(
            DB::Conn(&db),
            &ok_id,
            "lifecycle-webhook",
            200,
            Some(r#"{"received":true}"#.to_string()),
        )
        .await
        .expect("mark successful");
        WebhookDeliveryStore::schedule_retry_for_webhook(
            DB::Conn(&db),
            &retry_id,
            "lifecycle-webhook",
            (Utc::now() + chrono::Duration::seconds(60)).naive_utc(),
            Some("upstream exploded".to_string()),
            Some((500, Some("boom".to_string()))),
        )
        .await
        .expect("schedule retry");
        WebhookDeliveryStore::mark_as_failed_permanently_for_webhook(
            DB::Conn(&db),
            &dead_id,
            "lifecycle-webhook",
            Some("gone forever".to_string()),
            Some((410, None)),
        )
        .await
        .expect("fail permanently");

        let all = WebhookDeliveryStore::get_deliveries_with_filters(
            DB::Conn(&db),
            "lifecycle-webhook",
            None,
            None,
            50,
            0,
        )
        .await
        .expect("list all");
        assert_eq!(all.len(), 3);
        let total = WebhookDeliveryStore::count_deliveries_with_filters(
            DB::Conn(&db),
            "lifecycle-webhook",
            None,
            None,
        )
        .await
        .expect("count all");
        assert_eq!(total, 3);

        // Cross-webhook authorization is refused: another webhook id cannot
        // claim this delivery.
        let claimed = WebhookDeliveryStore::find_authorized_open_delivery(
            DB::Conn(&db),
            &ok_id,
            "some-other-webhook",
        )
        .await
        .expect("query unauthorized claim");
        assert!(claimed.is_none());
    }
}
