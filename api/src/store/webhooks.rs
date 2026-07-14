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
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        webhook_id: &str,
        org_id: &str,
        name: &str,
        url: &str,
        secret_encrypted: Vec<u8>,
        encryption_key_id: &str,
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
            secret: Set(String::new()),
            secret_encrypted: Set(Some(secret_encrypted)),
            encryption_key_id: Set(Some(encryption_key_id.to_string())),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
        DB,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    async fn setup_db() -> (sea_orm::DatabaseConnection, String, String) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "webhook-isolation-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "webhook-isolation-a",
            "Webhook Isolation A",
            &owner.id,
            None,
        )
        .await
        .expect("create organization A");
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "webhook-isolation-b",
            "Webhook Isolation B",
            &owner.id,
            None,
        )
        .await
        .expect("create organization B");

        (db, org_a.id, org_b.id)
    }

    async fn create_webhook(
        db: &sea_orm::DatabaseConnection,
        webhook_id: &str,
        org_id: &str,
        event: &str,
    ) {
        let now = chrono::Utc::now().naive_utc();
        WebhookStore::create(
            DB::Conn(db),
            webhook_id,
            org_id,
            webhook_id,
            &format!("https://{webhook_id}.example.test/events"),
            vec![1, 2, 3],
            "test-key",
            &serde_json::to_string(&[event]).expect("serialize events"),
            true,
            now,
            now,
        )
        .await
        .expect("create webhook");
    }

    #[tokio::test]
    async fn webhook_lists_and_event_selection_are_organization_scoped() {
        let (db, org_a, org_b) = setup_db().await;
        create_webhook(&db, "webhook-a", &org_a, "user.signup.success").await;
        create_webhook(&db, "webhook-b", &org_b, "user.signup.success").await;

        let org_a_webhooks = WebhookStore::find_by_organization(DB::Conn(&db), &org_a)
            .await
            .expect("list organization A webhooks");
        assert_eq!(org_a_webhooks.len(), 1);
        assert_eq!(org_a_webhooks[0].id, "webhook-a");
        assert_eq!(
            WebhookStore::count_by_organization(DB::Conn(&db), &org_a)
                .await
                .expect("count organization A webhooks"),
            1
        );

        let org_a_event_webhooks = WebhookStore::find_active_webhooks_for_event(
            DB::Conn(&db),
            &org_a,
            "user.signup.success",
        )
        .await
        .expect("select organization A event webhooks");
        assert_eq!(org_a_event_webhooks.len(), 1);
        assert_eq!(org_a_event_webhooks[0].id, "webhook-a");

        assert!(
            WebhookStore::find_by_organization(DB::Conn(&db), "missing-org")
                .await
                .expect("list missing organization")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn webhook_mutations_deny_other_organization_and_missing_ids() {
        let (db, org_a, org_b) = setup_db().await;
        create_webhook(&db, "webhook-a", &org_a, "user.signup.success").await;
        let now = chrono::Utc::now().naive_utc();

        WebhookStore::update_name(DB::Conn(&db), "webhook-a", &org_a, "allowed", now)
            .await
            .expect("same-organization update succeeds");

        for result in [
            WebhookStore::update_url(
                DB::Conn(&db),
                "webhook-a",
                &org_b,
                "https://attacker.example.test/events",
                now,
            )
            .await,
            WebhookStore::update_events(
                DB::Conn(&db),
                "webhook-a",
                &org_b,
                r#"["organization.updated"]"#,
                now,
            )
            .await,
            WebhookStore::update_is_active(DB::Conn(&db), "webhook-a", &org_b, false, now).await,
        ] {
            assert!(matches!(result, Err(crate::error::AppError::NotFound(_))));
        }

        let after_denied_updates = WebhookStore::find_by_id(DB::Conn(&db), "webhook-a")
            .await
            .expect("load webhook after denied updates")
            .expect("webhook remains");
        assert_eq!(after_denied_updates.name, "allowed");
        assert_eq!(
            after_denied_updates.url,
            "https://webhook-a.example.test/events"
        );
        assert_eq!(after_denied_updates.events, r#"["user.signup.success"]"#);
        assert!(after_denied_updates.is_active);

        let missing_update =
            WebhookStore::update_name(DB::Conn(&db), "missing-webhook", &org_a, "missing", now)
                .await;
        assert!(matches!(
            missing_update,
            Err(crate::error::AppError::NotFound(_))
        ));

        let wrong_org_delete = WebhookStore::delete(DB::Conn(&db), "webhook-a", &org_b).await;
        assert!(matches!(
            wrong_org_delete,
            Err(crate::error::AppError::NotFound(_))
        ));
        assert!(WebhookStore::find_by_id(DB::Conn(&db), "webhook-a")
            .await
            .expect("load webhook after denied delete")
            .is_some());

        let missing_delete = WebhookStore::delete(DB::Conn(&db), "missing-webhook", &org_a).await;
        assert!(matches!(
            missing_delete,
            Err(crate::error::AppError::NotFound(_))
        ));

        WebhookStore::delete(DB::Conn(&db), "webhook-a", &org_a)
            .await
            .expect("same-organization delete succeeds");
        assert!(WebhookStore::find_by_id(DB::Conn(&db), "webhook-a")
            .await
            .expect("load deleted webhook")
            .is_none());
    }
}
