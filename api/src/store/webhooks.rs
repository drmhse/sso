use crate::entities::prelude::Webhooks;
use crate::entities::webhooks;
use crate::error::Result;
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter, Set,
};

pub struct WebhookStore;

impl WebhookStore {
    /// Find a webhook by ID
    pub async fn find_by_id(db: DB<'_>, webhook_id: &str) -> Result<Option<webhooks::Model>> {
        let result = Webhooks::find()
            .filter(webhooks::Column::Id.eq(webhook_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a webhook by organization ID and name
    pub async fn find_by_org_and_name(
        db: DB<'_>,
        org_id: &str,
        name: &str,
    ) -> Result<Option<webhooks::Model>> {
        let result = Webhooks::find()
            .filter(webhooks::Column::OrgId.eq(org_id))
            .filter(webhooks::Column::Name.eq(name))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find all webhooks for an organization
    pub async fn find_by_organization(db: DB<'_>, org_id: &str) -> Result<Vec<webhooks::Model>> {
        let webhooks = Webhooks::find()
            .filter(webhooks::Column::OrgId.eq(org_id))
            .all(&db)
            .await?;

        Ok(webhooks)
    }

    /// Find all active webhooks for an organization that subscribe to a specific event type
    pub async fn find_active_webhooks_for_event(
        db: DB<'_>,
        org_id: &str,
        event_type: &str,
    ) -> Result<Vec<webhooks::Model>> {
        // Get all active webhooks for this organization
        // Filter by event type in application layer since events is a JSON array
        let all_webhooks = Webhooks::find()
            .filter(webhooks::Column::OrgId.eq(org_id))
            .filter(webhooks::Column::IsActive.eq(true))
            .all(&db)
            .await?;

        // Filter in Rust to avoid complex SQL generation issues
        let webhooks = all_webhooks
            .into_iter()
            .filter(|w| {
                let events: Vec<String> = serde_json::from_str(&w.events).unwrap_or_default();
                events.contains(&event_type.to_string())
            })
            .collect();

        Ok(webhooks)
    }

    /// Create a new webhook
    pub async fn create(
        db: DB<'_>,
        webhook_id: &str,
        org_id: &str,
        name: &str,
        url: &str,
        secret: &str,
        events: &str,
        is_active: bool,
        created_at: chrono::NaiveDateTime,
        updated_at: chrono::NaiveDateTime,
    ) -> Result<()> {
        let new_webhook = webhooks::ActiveModel {
            id: Set(webhook_id.to_string()),
            org_id: Set(org_id.to_string()),
            name: Set(name.to_string()),
            url: Set(url.to_string()),
            secret: Set(secret.to_string()),
            events: Set(events.to_string()),
            is_active: Set(is_active),
            created_at: Set(created_at),
            updated_at: Set(updated_at),
        };

        // Handle unique constraint violations gracefully
        let mut attempts = 0;
        let max_retries = 5;
        loop {
            attempts += 1;
            match new_webhook.clone().insert(&db).await {
                Ok(_) => return Ok(()),
                Err(sea_orm::DbErr::Query(sea_orm::RuntimeErr::SqlxError(
                    sqlx::Error::Database(db_err),
                ))) if db_err.is_unique_violation() => {
                    return Err(crate::error::AppError::DuplicateConstraint(
                        "A webhook with this name already exists in this organization".to_string(),
                    ));
                }
                Err(e) if crate::error::is_deadlock_error(&e) && attempts <= max_retries => {
                    let delay_ms = 10 * (1 << attempts.min(6));
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Count webhooks by organization
    pub async fn count_by_organization(db: DB<'_>, org_id: &str) -> Result<i64> {
        let count = Webhooks::find()
            .filter(webhooks::Column::OrgId.eq(org_id))
            .count(&db)
            .await? as i64;
        Ok(count)
    }

    /// Update webhook name
    pub async fn update_name(
        db: DB<'_>,
        webhook_id: &str,
        org_id: &str,
        name: &str,
        updated_at: NaiveDateTime,
    ) -> Result<()> {
        let webhook = Webhooks::find()
            .filter(webhooks::Column::Id.eq(webhook_id))
            .filter(webhooks::Column::OrgId.eq(org_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Webhook not found".to_string()))?;

        let mut active_webhook = webhook.into_active_model();
        active_webhook.name = Set(name.to_string());
        active_webhook.updated_at = Set(updated_at);
        active_webhook.update(&db).await?;
        Ok(())
    }

    /// Update webhook URL
    pub async fn update_url(
        db: DB<'_>,
        webhook_id: &str,
        org_id: &str,
        url: &str,
        updated_at: NaiveDateTime,
    ) -> Result<()> {
        let webhook = Webhooks::find()
            .filter(webhooks::Column::Id.eq(webhook_id))
            .filter(webhooks::Column::OrgId.eq(org_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Webhook not found".to_string()))?;

        let mut active_webhook = webhook.into_active_model();
        active_webhook.url = Set(url.to_string());
        active_webhook.updated_at = Set(updated_at);
        active_webhook.update(&db).await?;
        Ok(())
    }

    /// Update webhook events
    pub async fn update_events(
        db: DB<'_>,
        webhook_id: &str,
        org_id: &str,
        events: &str,
        updated_at: NaiveDateTime,
    ) -> Result<()> {
        let webhook = Webhooks::find()
            .filter(webhooks::Column::Id.eq(webhook_id))
            .filter(webhooks::Column::OrgId.eq(org_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Webhook not found".to_string()))?;

        let mut active_webhook = webhook.into_active_model();
        active_webhook.events = Set(events.to_string());
        active_webhook.updated_at = Set(updated_at);
        active_webhook.update(&db).await?;
        Ok(())
    }

    /// Update webhook is_active status
    pub async fn update_is_active(
        db: DB<'_>,
        webhook_id: &str,
        org_id: &str,
        is_active: bool,
        updated_at: NaiveDateTime,
    ) -> Result<()> {
        let webhook = Webhooks::find()
            .filter(webhooks::Column::Id.eq(webhook_id))
            .filter(webhooks::Column::OrgId.eq(org_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Webhook not found".to_string()))?;

        let mut active_webhook = webhook.into_active_model();
        active_webhook.is_active = Set(is_active);
        active_webhook.updated_at = Set(updated_at);
        active_webhook.update(&db).await?;
        Ok(())
    }

    /// Delete a webhook
    pub async fn delete(db: DB<'_>, webhook_id: &str, org_id: &str) -> Result<()> {
        let result = Webhooks::delete_many()
            .filter(webhooks::Column::Id.eq(webhook_id))
            .filter(webhooks::Column::OrgId.eq(org_id))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(crate::error::AppError::NotFound(
                "Webhook not found".to_string(),
            ));
        }

        Ok(())
    }
}
