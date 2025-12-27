use crate::db::models::WebhookDeliveryWithWebhook;
use crate::entities::prelude::{WebhookDeliveries, Webhooks};
use crate::entities::webhook_deliveries;
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use uuid::Uuid;

pub struct WebhookDeliveryStore;

impl WebhookDeliveryStore {
    /// Get pending webhook deliveries that are ready to be processed
    pub async fn get_pending_deliveries(
        db: DB<'_>,
        limit: u64,
    ) -> Result<Vec<webhook_deliveries::Model>> {
        use sea_orm::{Condition, QueryOrder};

        let now = Utc::now().naive_utc();

        // Get all pending deliveries using SeaORM for database agnosticism
        let all_deliveries = WebhookDeliveries::find()
            .filter(webhook_deliveries::Column::Delivered.eq(false))
            .filter(
                Condition::any()
                    .add(webhook_deliveries::Column::NextRetryAt.is_null())
                    .add(webhook_deliveries::Column::NextRetryAt.lte(now)),
            )
            .order_by_asc(webhook_deliveries::Column::CreatedAt)
            .all(&db)
            .await?;

        // Filter in application layer to check webhook is_active and attempt_count
        let mut result = Vec::new();
        for delivery in all_deliveries {
            if delivery.attempt_count >= delivery.max_attempts {
                continue;
            }

            // Check if webhook is active
            if let Ok(Some(webhook)) = Webhooks::find_by_id(&delivery.webhook_id).one(&db).await {
                if webhook.is_active {
                    result.push(delivery);
                    if result.len() >= limit as usize {
                        break;
                    }
                }
            }
        }

        Ok(result)
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
            .limit(limit as u64)
            .offset(offset as u64)
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
