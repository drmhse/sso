//! Durable audit outbox and reconciliation worker.
//!
//! Login, organization, MFA, and platform events are serialized into `audit_outbox`
//! before enqueue reports success. The background worker then delivers pending
//! rows to their final audit tables in a same-database transaction. Security-
//! critical callers share their domain transaction with the `log_*_with_db`
//! methods so a mutation and its success event commit or roll back together.

use crate::db::DB;
use crate::entities::{
    audit_outbox, login_events, mfa_audit_log, organization_audit_log, platform_audit_log,
};
use crate::error::AppError;
use anyhow::{anyhow, Context, Result as AnyResult};
use chrono::Timelike;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration, MissedTickBehavior};
use uuid::Uuid;

const PENDING: &str = "pending";
const DEAD_LETTER: &str = "dead_letter";
#[cfg(not(test))]
const DELIVERY_BATCH_SIZE: u64 = 100;
#[cfg(test)]
const DELIVERY_BATCH_SIZE: u64 = 5;
#[cfg(not(test))]
const MAX_BATCHES_PER_WAKE: usize = 100;
#[cfg(test)]
const MAX_BATCHES_PER_WAKE: usize = 2;
const MAX_DELIVERY_ATTEMPTS: i32 = 10;
const RECONCILER_CONCURRENCY: &str = "single worker per database is the qualified topology";

/// Durably enqueue a platform event through the common outbox when a legacy
/// helper has only a generic connection. The periodic reconciler discovers the
/// row even though this path has no actor wake handle.
pub async fn enqueue_platform_with_connection<C>(
    db: &C,
    model: platform_audit_log::ActiveModel,
) -> crate::error::Result<()>
where
    C: ConnectionTrait,
{
    let event = normalize_platform(model).map_err(AppError::Audit)?;
    insert_outbox(db, AuditPayload::Platform(event)).await
}

pub async fn enqueue_mfa_with_connection<C>(
    db: &C,
    model: mfa_audit_log::ActiveModel,
) -> crate::error::Result<()>
where
    C: ConnectionTrait,
{
    let event = normalize_mfa(model).map_err(AppError::Audit)?;
    insert_outbox(db, AuditPayload::Mfa(event)).await
}

pub async fn enqueue_org_with_connection<C>(
    db: &C,
    model: organization_audit_log::ActiveModel,
) -> crate::error::Result<()>
where
    C: ConnectionTrait,
{
    let event = normalize_org(model).map_err(AppError::Audit)?;
    insert_outbox(db, AuditPayload::Organization(event)).await
}

pub async fn enqueue_login_with_connection<C>(
    db: &C,
    model: login_events::ActiveModel,
) -> crate::error::Result<login_events::Model>
where
    C: ConnectionTrait,
{
    let event = normalize_login(model).map_err(AppError::Audit)?;
    insert_outbox(db, AuditPayload::Login(event.clone())).await?;
    Ok(event)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "event", rename_all = "snake_case")]
enum AuditPayload {
    Login(login_events::Model),
    Organization(organization_audit_log::Model),
    Mfa(mfa_audit_log::Model),
    Platform(platform_audit_log::Model),
}

impl AuditPayload {
    fn event_id(&self) -> &str {
        match self {
            Self::Login(event) => &event.id,
            Self::Organization(event) => &event.id,
            Self::Mfa(event) => &event.id,
            Self::Platform(event) => &event.id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Login(_) => "login",
            Self::Organization(_) => "organization",
            Self::Mfa(_) => "mfa",
            Self::Platform(_) => "platform",
        }
    }
}

pub enum AuditMsg {
    Wake,
    Shutdown(oneshot::Sender<bool>),
}

/// Handle that durably enqueues audit events and wakes the reconciliation task.
#[derive(Clone)]
pub struct AuditHandle {
    sender: mpsc::Sender<AuditMsg>,
    db: DatabaseConnection,
}

impl AuditHandle {
    pub fn new(db: DatabaseConnection) -> Self {
        let (sender, receiver) = mpsc::channel(1_024);
        let actor = AuditActor::new(db.clone(), receiver);
        tokio::spawn(actor.run());
        tracing::info!(
            concurrency = RECONCILER_CONCURRENCY,
            "Durable audit outbox reconciler started"
        );
        Self { sender, db }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn without_worker(db: DatabaseConnection) -> Self {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        Self { sender, db }
    }

    /// Return only after the login event exists in the durable outbox.
    pub async fn log_login(&self, model: login_events::ActiveModel) -> crate::error::Result<()> {
        self.log_login_with_db(DB::Conn(&self.db), model).await
    }

    /// Enqueue a login event on the caller's connection or transaction.
    pub async fn log_login_with_db(
        &self,
        db: DB<'_>,
        model: login_events::ActiveModel,
    ) -> crate::error::Result<()> {
        let event = normalize_login(model).map_err(AppError::Audit)?;
        self.enqueue(db, AuditPayload::Login(event)).await
    }

    /// Return only after the organization event exists in the durable outbox.
    pub async fn log_org(
        &self,
        model: organization_audit_log::ActiveModel,
    ) -> crate::error::Result<()> {
        self.log_org_with_db(DB::Conn(&self.db), model).await
    }

    /// Enqueue an organization event on the caller's connection or transaction.
    pub async fn log_org_with_db(
        &self,
        db: DB<'_>,
        model: organization_audit_log::ActiveModel,
    ) -> crate::error::Result<()> {
        let event = normalize_org(model).map_err(AppError::Audit)?;
        self.enqueue(db, AuditPayload::Organization(event)).await
    }

    /// Return only after the MFA event exists in the durable outbox.
    pub async fn log_mfa(&self, model: mfa_audit_log::ActiveModel) -> crate::error::Result<()> {
        self.log_mfa_with_db(DB::Conn(&self.db), model).await
    }

    /// Enqueue an MFA event on the caller's connection or transaction.
    pub async fn log_mfa_with_db(
        &self,
        db: DB<'_>,
        model: mfa_audit_log::ActiveModel,
    ) -> crate::error::Result<()> {
        let event = normalize_mfa(model).map_err(AppError::Audit)?;
        self.enqueue(db, AuditPayload::Mfa(event)).await
    }

    /// Return only after the platform event exists in the durable outbox.
    pub async fn log_platform(
        &self,
        model: platform_audit_log::ActiveModel,
    ) -> crate::error::Result<()> {
        self.log_platform_with_db(DB::Conn(&self.db), model).await
    }

    /// Enqueue a platform event on the caller's connection or transaction.
    pub async fn log_platform_with_db(
        &self,
        db: DB<'_>,
        model: platform_audit_log::ActiveModel,
    ) -> crate::error::Result<()> {
        let event = normalize_platform(model).map_err(AppError::Audit)?;
        self.enqueue(db, AuditPayload::Platform(event)).await
    }

    async fn enqueue(&self, db: DB<'_>, payload: AuditPayload) -> crate::error::Result<()> {
        self.enqueue_on_connection(&db, payload).await
    }

    async fn enqueue_on_connection<C>(
        &self,
        db: &C,
        payload: AuditPayload,
    ) -> crate::error::Result<()>
    where
        C: ConnectionTrait,
    {
        insert_outbox(db, payload).await?;

        // The row is already durable. A full/closed wake channel is harmless:
        // startup and periodic reconciliation will discover it.
        let _ = self.sender.try_send(AuditMsg::Wake);
        Ok(())
    }

    pub async fn shutdown(&self) {
        let (sender, receiver) = oneshot::channel();
        if self.sender.send(AuditMsg::Shutdown(sender)).await.is_err() {
            tracing::warn!("Audit reconciler was already stopped; durable rows remain replayable");
            return;
        }
        match receiver.await {
            Ok(true) => tracing::info!("Audit reconciler shutdown completed with no pending rows"),
            Ok(false) => tracing::warn!(
                "Audit reconciler shutdown left durable pending rows for restart reconciliation"
            ),
            Err(_) => tracing::warn!("Audit reconciler shutdown acknowledgement was dropped"),
        }
    }
}

async fn insert_outbox<C>(db: &C, payload: AuditPayload) -> crate::error::Result<()>
where
    C: ConnectionTrait,
{
    let now = chrono::Utc::now().naive_utc();
    let serialized = serde_json::to_string(&payload)
        .context("audit event could not be serialized for durable enqueue")
        .map_err(AppError::Audit)?;
    audit_outbox::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        event_id: Set(payload.event_id().to_string()),
        event_kind: Set(payload.kind().to_string()),
        payload: Set(serialized),
        status: Set(PENDING.to_string()),
        attempts: Set(0),
        available_at: Set(now),
        last_error_code: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        dead_lettered_at: Set(None),
    }
    .insert(db)
    .await
    .map_err(AppError::SeaOrmDatabase)?;
    Ok(())
}

fn normalize_login(mut model: login_events::ActiveModel) -> AnyResult<login_events::Model> {
    let now = canonical_timestamp(chrono::Utc::now().naive_utc());
    Ok(login_events::Model {
        id: required(model.id.take(), "login.id")?,
        user_id: required(model.user_id.take(), "login.user_id")?,
        service_id: model.service_id.take().unwrap_or(None),
        org_id: model.org_id.take().unwrap_or(None),
        provider: required(model.provider.take(), "login.provider")?,
        ip_address: model.ip_address.take().unwrap_or(None),
        user_agent: model.user_agent.take().unwrap_or(None),
        created_at: canonical_timestamp(model.created_at.take().unwrap_or(now)),
        risk_score: model.risk_score.take().unwrap_or(None),
        risk_factors: model.risk_factors.take().unwrap_or(None),
        geo_country: model.geo_country.take().unwrap_or(None),
        geo_city: model.geo_city.take().unwrap_or(None),
        geo_lat: model.geo_lat.take().unwrap_or(None),
        geo_long: model.geo_long.take().unwrap_or(None),
    })
}

fn normalize_org(
    mut model: organization_audit_log::ActiveModel,
) -> AnyResult<organization_audit_log::Model> {
    let now = canonical_timestamp(chrono::Utc::now().naive_utc());
    Ok(organization_audit_log::Model {
        id: required(model.id.take(), "organization.id")?,
        org_id: required(model.org_id.take(), "organization.org_id")?,
        actor_user_id: required(model.actor_user_id.take(), "organization.actor_user_id")?,
        action: required(model.action.take(), "organization.action")?,
        target_type: required(model.target_type.take(), "organization.target_type")?,
        target_id: required(model.target_id.take(), "organization.target_id")?,
        ip_address: model.ip_address.take().unwrap_or(None),
        user_agent: model.user_agent.take().unwrap_or(None),
        success: model.success.take().unwrap_or(true),
        details: model.details.take().unwrap_or(None),
        created_at: canonical_timestamp(model.created_at.take().unwrap_or(now)),
    })
}

fn normalize_mfa(mut model: mfa_audit_log::ActiveModel) -> AnyResult<mfa_audit_log::Model> {
    let now = canonical_timestamp(chrono::Utc::now().naive_utc());
    Ok(mfa_audit_log::Model {
        id: required(model.id.take(), "mfa.id")?,
        org_id: model.org_id.take().unwrap_or(None),
        user_id: required(model.user_id.take(), "mfa.user_id")?,
        event_type: required(model.event_type.take(), "mfa.event_type")?,
        ip_address: model.ip_address.take().unwrap_or(None),
        user_agent: model.user_agent.take().unwrap_or(None),
        success: required(model.success.take(), "mfa.success")?,
        details: model.details.take().unwrap_or(None),
        created_at: canonical_timestamp(model.created_at.take().unwrap_or(now)),
    })
}

fn normalize_platform(
    mut model: platform_audit_log::ActiveModel,
) -> AnyResult<platform_audit_log::Model> {
    let now = canonical_timestamp(chrono::Utc::now().naive_utc());
    Ok(platform_audit_log::Model {
        id: required(model.id.take(), "platform.id")?,
        platform_owner_id: required(model.platform_owner_id.take(), "platform.platform_owner_id")?,
        action: required(model.action.take(), "platform.action")?,
        target_type: required(model.target_type.take(), "platform.target_type")?,
        target_id: required(model.target_id.take(), "platform.target_id")?,
        metadata: model.metadata.take().unwrap_or(None),
        created_at: canonical_timestamp(model.created_at.take().unwrap_or(now)),
    })
}

fn required<T>(value: Option<T>, field: &'static str) -> AnyResult<T> {
    value.ok_or_else(|| anyhow!("audit event is missing required field {field}"))
}

fn canonical_timestamp(value: chrono::NaiveDateTime) -> chrono::NaiveDateTime {
    value
        .with_nanosecond(0)
        .expect("zero nanoseconds is a valid timestamp")
}

struct AuditActor {
    db: DatabaseConnection,
    receiver: mpsc::Receiver<AuditMsg>,
}

impl AuditActor {
    fn new(db: DatabaseConnection, receiver: mpsc::Receiver<AuditMsg>) -> Self {
        Self { db, receiver }
    }

    async fn run(mut self) {
        // Reconcile rows from a prior process before waiting for new messages.
        self.reconcile_and_report().await;
        let mut ticker = interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.reconcile_and_report().await;
                }
                message = self.receiver.recv() => match message {
                    Some(AuditMsg::Wake) => {
                        self.reconcile_and_report().await;
                    }
                    Some(AuditMsg::Shutdown(reply)) => {
                        let drained = self.drain_available().await.unwrap_or(false);
                        let _ = reply.send(drained);
                        return;
                    }
                    None => {
                        self.reconcile_and_report().await;
                        return;
                    }
                }
            }
        }
    }

    async fn reconcile_and_report(&self) {
        if self.drain_available().await.is_err() {
            tracing::error!(
                error_code = "database_error",
                "Audit outbox reconciliation could not scan durable state"
            );
        }
    }

    /// Deliver all currently eligible rows. Returns true only when no pending
    /// row remains (future-backoff rows make shutdown report incomplete).
    async fn drain_available(&self) -> AnyResult<bool> {
        for _ in 0..MAX_BATCHES_PER_WAKE {
            let now = chrono::Utc::now().naive_utc();
            let rows = audit_outbox::Entity::find()
                .filter(audit_outbox::Column::Status.eq(PENDING))
                .filter(audit_outbox::Column::AvailableAt.lte(now))
                .order_by_asc(audit_outbox::Column::CreatedAt)
                .order_by_asc(audit_outbox::Column::Id)
                .limit(DELIVERY_BATCH_SIZE)
                .all(&self.db)
                .await
                .context("audit outbox scan failed")?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                if !self.deliver(row).await {
                    return Ok(false);
                }
            }
        }

        Ok(audit_outbox::Entity::find()
            .filter(audit_outbox::Column::Status.eq(PENDING))
            .one(&self.db)
            .await
            .context("audit outbox pending-state check failed")?
            .is_none())
    }

    async fn deliver(&self, row: audit_outbox::Model) -> bool {
        let payload = match serde_json::from_str::<AuditPayload>(&row.payload) {
            Ok(payload)
                if payload.kind() == row.event_kind && payload.event_id() == row.event_id =>
            {
                payload
            }
            _ => {
                return self.dead_letter(&row, "invalid_payload").await;
            }
        };

        let transaction = match self.db.begin().await {
            Ok(transaction) => transaction,
            Err(_) => {
                return self.record_failure(&row, "database_unavailable").await;
            }
        };

        let delivery = match payload {
            AuditPayload::Login(event) => deliver_login(&transaction, event).await,
            AuditPayload::Organization(event) => deliver_org(&transaction, event).await,
            AuditPayload::Mfa(event) => deliver_mfa(&transaction, event).await,
            AuditPayload::Platform(event) => deliver_platform(&transaction, event).await,
        };
        if let Err(code) = delivery {
            let _ = transaction.rollback().await;
            if code == "event_id_conflict" {
                return self.dead_letter(&row, code).await;
            } else {
                return self.record_failure(&row, code).await;
            }
        }

        if audit_outbox::Entity::delete_by_id(row.id.clone())
            .exec(&transaction)
            .await
            .is_err()
        {
            let _ = transaction.rollback().await;
            return self.record_failure(&row, "database_error").await;
        }
        match transaction.commit().await {
            Ok(()) => {
                tracing::debug!(
                    outbox_id = %row.id,
                    event_kind = %row.event_kind,
                    "Audit outbox row delivered"
                );
                true
            }
            Err(_) => self.record_failure(&row, "database_error").await,
        }
    }

    async fn record_failure(&self, row: &audit_outbox::Model, error_code: &'static str) -> bool {
        let now = chrono::Utc::now().naive_utc();
        let attempts = row.attempts.saturating_add(1);
        let dead = attempts >= MAX_DELIVERY_ATTEMPTS;
        let delay_seconds = i64::from(1_i32.checked_shl(attempts.min(8) as u32).unwrap_or(256));
        let mut active: audit_outbox::ActiveModel = row.clone().into();
        active.attempts = Set(attempts);
        active.last_error_code = Set(Some(error_code.to_string()));
        active.updated_at = Set(now);
        active.status = Set(if dead { DEAD_LETTER } else { PENDING }.to_string());
        active.available_at = Set(now + chrono::Duration::seconds(delay_seconds));
        active.dead_lettered_at = Set(dead.then_some(now));
        if active.update(&self.db).await.is_err() {
            tracing::error!(
                outbox_id = %row.id,
                event_kind = %row.event_kind,
                "Audit delivery failed and its retry state could not be persisted"
            );
            false
        } else {
            tracing::warn!(
                outbox_id = %row.id,
                event_kind = %row.event_kind,
                attempt = attempts,
                error_code,
                dead_letter = dead,
                "Audit delivery deferred"
            );
            true
        }
    }

    async fn dead_letter(&self, row: &audit_outbox::Model, error_code: &'static str) -> bool {
        let now = chrono::Utc::now().naive_utc();
        let mut active: audit_outbox::ActiveModel = row.clone().into();
        active.attempts = Set(row.attempts.saturating_add(1));
        active.last_error_code = Set(Some(error_code.to_string()));
        active.status = Set(DEAD_LETTER.to_string());
        active.updated_at = Set(now);
        active.dead_lettered_at = Set(Some(now));
        if active.update(&self.db).await.is_err() {
            tracing::error!(
                outbox_id = %row.id,
                event_kind = %row.event_kind,
                "Invalid audit row could not be moved to dead-letter state"
            );
            false
        } else {
            tracing::error!(
                outbox_id = %row.id,
                event_kind = %row.event_kind,
                error_code,
                "Audit outbox row moved to dead-letter state"
            );
            true
        }
    }
}

async fn deliver_login(
    transaction: &sea_orm::DatabaseTransaction,
    event: login_events::Model,
) -> std::result::Result<(), &'static str> {
    match login_events::Entity::find_by_id(event.id.clone())
        .one(transaction)
        .await
        .map_err(|_| "database_error")?
    {
        Some(existing) if existing == event => Ok(()),
        Some(_) => Err("event_id_conflict"),
        None => event
            .into_active_model()
            .insert(transaction)
            .await
            .map(|_| ())
            .map_err(|_| "database_error"),
    }
}

async fn deliver_org(
    transaction: &sea_orm::DatabaseTransaction,
    event: organization_audit_log::Model,
) -> std::result::Result<(), &'static str> {
    match crate::entities::prelude::OrganizationAuditLog::find_by_id(event.id.clone())
        .one(transaction)
        .await
        .map_err(|_| "database_error")?
    {
        Some(existing) if existing == event => Ok(()),
        Some(_) => Err("event_id_conflict"),
        None => event
            .into_active_model()
            .insert(transaction)
            .await
            .map(|_| ())
            .map_err(|_| "database_error"),
    }
}

async fn deliver_mfa(
    transaction: &sea_orm::DatabaseTransaction,
    event: mfa_audit_log::Model,
) -> std::result::Result<(), &'static str> {
    match mfa_audit_log::Entity::find_by_id(event.id.clone())
        .one(transaction)
        .await
        .map_err(|_| "database_error")?
    {
        Some(existing) if existing == event => Ok(()),
        Some(_) => Err("event_id_conflict"),
        None => event
            .into_active_model()
            .insert(transaction)
            .await
            .map(|_| ())
            .map_err(|_| "database_error"),
    }
}

async fn deliver_platform(
    transaction: &sea_orm::DatabaseTransaction,
    event: platform_audit_log::Model,
) -> std::result::Result<(), &'static str> {
    match platform_audit_log::Entity::find_by_id(event.id.clone())
        .one(transaction)
        .await
        .map_err(|_| "database_error")?
    {
        Some(existing) if existing == event => Ok(()),
        Some(_) => Err("event_id_conflict"),
        None => event
            .into_active_model()
            .insert(transaction)
            .await
            .map(|_| ())
            .map_err(|_| "database_error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveValue::Set, Database, PaginatorTrait, TransactionTrait};

    fn login_event(id: &str, user_id: &str) -> login_events::ActiveModel {
        login_events::ActiveModel {
            id: Set(id.to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(None),
            org_id: Set(None),
            provider: Set("password".to_string()),
            ..Default::default()
        }
    }

    fn organization_event(
        id: &str,
        org_id: &str,
        actor_user_id: &str,
        action: &str,
        target_id: &str,
    ) -> organization_audit_log::ActiveModel {
        organization_audit_log::ActiveModel {
            id: Set(id.to_string()),
            org_id: Set(org_id.to_string()),
            actor_user_id: Set(actor_user_id.to_string()),
            action: Set(action.to_string()),
            target_type: Set("organization_role".to_string()),
            target_id: Set(target_id.to_string()),
            success: Set(true),
            ..Default::default()
        }
    }

    fn platform_event(
        id: &str,
        owner_id: &str,
        action: &str,
        target_id: &str,
    ) -> platform_audit_log::ActiveModel {
        platform_audit_log::ActiveModel {
            id: Set(id.to_string()),
            platform_owner_id: Set(owner_id.to_string()),
            action: Set(action.to_string()),
            target_type: Set("organization".to_string()),
            target_id: Set(target_id.to_string()),
            metadata: Set(Some("{\"preserved\":true}".to_string())),
            ..Default::default()
        }
    }

    async fn database() -> DatabaseConnection {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&database, None).await.unwrap();
        database
    }

    async fn user(database: &DatabaseConnection, email: &str) -> crate::entities::users::Model {
        crate::store::users::UserStore::create(crate::db::DB::Conn(database), email, None, true)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn durable_enqueue_survives_closed_channel_and_restart_replays_it() {
        let database = database().await;
        let user = user(&database, "audit-restart@example.test").await;
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };
        handle
            .log_login(login_event("restart-event", &user.id))
            .await
            .unwrap();
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            1
        );
        assert_eq!(
            login_events::Entity::find().count(&database).await.unwrap(),
            0
        );

        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database.clone(), receiver);
        assert!(actor.drain_available().await.unwrap());
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            0
        );
        assert_eq!(
            login_events::Entity::find().count(&database).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn database_outage_is_returned_before_enqueue_success() {
        let database = database().await;
        let (sender, _receiver) = mpsc::channel(1);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };
        database.close().await.unwrap();
        let error = handle
            .log_login(login_event("outage-event", "user"))
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(matches!(error, AppError::SeaOrmDatabase(_)));
        assert!(!message.contains("audit-secret"));
    }

    #[tokio::test]
    async fn transaction_scoped_audit_failure_rolls_back_domain_mutation() {
        let database = database().await;
        let owner = user(&database, "audit-atomic-owner@example.test").await;
        let organization = crate::store::organizations::OrganizationStore::create(
            DB::Conn(&database),
            "audit-atomic",
            "Audit Atomic",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };
        let duplicate_event = organization_event(
            "atomic-event",
            &organization.id,
            &owner.id,
            "organization_role.created",
            "atomic-role",
        );
        handle.log_org(duplicate_event.clone()).await.unwrap();

        let transaction = database.begin().await.unwrap();
        crate::store::organization_roles::OrganizationRoleStore::create(
            DB::Tx(&transaction),
            "atomic-role",
            &organization.id,
            "atomic-role",
            "Atomic Role",
            None,
            serde_json::json!([]),
        )
        .await
        .unwrap();
        let error = handle
            .log_org_with_db(DB::Tx(&transaction), duplicate_event)
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::SeaOrmDatabase(_)));
        transaction.rollback().await.unwrap();

        assert!(
            crate::store::organization_roles::OrganizationRoleStore::find_by_id(
                DB::Conn(&database),
                "atomic-role",
            )
            .await
            .unwrap()
            .is_none()
        );
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn later_domain_failure_rolls_back_earlier_success_event() {
        let database = database().await;
        let owner = user(&database, "audit-order-owner@example.test").await;
        let organization = crate::store::organizations::OrganizationStore::create(
            DB::Conn(&database),
            "audit-order",
            "Audit Order",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };

        let transaction = database.begin().await.unwrap();
        crate::store::organization_roles::OrganizationRoleStore::create(
            DB::Tx(&transaction),
            "ordered-role",
            &organization.id,
            "ordered-role",
            "Ordered Role",
            None,
            serde_json::json!([]),
        )
        .await
        .unwrap();
        handle
            .log_org_with_db(
                DB::Tx(&transaction),
                organization_event(
                    "ordered-event",
                    &organization.id,
                    &owner.id,
                    "organization_role.created",
                    "ordered-role",
                ),
            )
            .await
            .unwrap();
        let later_error = crate::store::organization_roles::OrganizationRoleStore::create(
            DB::Tx(&transaction),
            "ordered-role",
            &organization.id,
            "ordered-role-duplicate",
            "Duplicate",
            None,
            serde_json::json!([]),
        )
        .await;
        assert!(later_error.is_err());
        transaction.rollback().await.unwrap();

        assert!(
            crate::store::organization_roles::OrganizationRoleStore::find_by_id(
                DB::Conn(&database),
                "ordered-role",
            )
            .await
            .unwrap()
            .is_none()
        );
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn deleted_organization_platform_event_replays_after_org_row_is_gone() {
        let database = database().await;
        let owner = user(&database, "deleted-org-audit-owner@example.test").await;
        let organization = crate::store::organizations::OrganizationStore::create(
            DB::Conn(&database),
            "deleted-org-audit",
            "Deleted Org Audit",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };

        let transaction = database.begin().await.unwrap();
        crate::store::organizations::OrganizationStore::delete(
            DB::Tx(&transaction),
            &organization.id,
        )
        .await
        .unwrap();
        handle
            .log_platform_with_db(
                DB::Tx(&transaction),
                platform_event(
                    "deleted-org-event",
                    &owner.id,
                    "org.deleted",
                    &organization.id,
                ),
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        assert!(crate::store::organizations::OrganizationStore::find_by_id(
            DB::Conn(&database),
            &organization.id,
        )
        .await
        .unwrap()
        .is_none());
        let actor = AuditActor::new(database.clone(), receiver);
        assert!(actor.drain_available().await.unwrap());
        let delivered = platform_audit_log::Entity::find_by_id("deleted-org-event")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.target_id, organization.id);
        assert_eq!(delivered.action, "org.deleted");
    }

    #[tokio::test]
    async fn deleted_organization_rolls_back_when_platform_audit_enqueue_fails() {
        let database = database().await;
        let owner = user(&database, "deleted-org-rollback-owner@example.test").await;
        let organization = crate::store::organizations::OrganizationStore::create(
            DB::Conn(&database),
            "deleted-org-rollback",
            "Deleted Org Rollback",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };
        let event = platform_event(
            "duplicate-deleted-org-event",
            &owner.id,
            "org.deleted",
            &organization.id,
        );
        handle.log_platform(event.clone()).await.unwrap();

        let transaction = database.begin().await.unwrap();
        crate::store::organizations::OrganizationStore::delete(
            DB::Tx(&transaction),
            &organization.id,
        )
        .await
        .unwrap();
        assert!(handle
            .log_platform_with_db(DB::Tx(&transaction), event)
            .await
            .is_err());
        transaction.rollback().await.unwrap();

        assert!(crate::store::organizations::OrganizationStore::find_by_id(
            DB::Conn(&database),
            &organization.id,
        )
        .await
        .unwrap()
        .is_some());
    }

    #[tokio::test]
    async fn duplicate_replay_is_idempotent_when_target_matches() {
        let database = database().await;
        let user = user(&database, "audit-duplicate@example.test").await;
        let event = normalize_login(login_event("duplicate-event", &user.id)).unwrap();
        event
            .clone()
            .into_active_model()
            .insert(&database)
            .await
            .unwrap();
        let payload = AuditPayload::Login(event);
        let now = chrono::Utc::now().naive_utc();
        audit_outbox::ActiveModel {
            id: Set("duplicate-outbox".to_string()),
            event_id: Set(payload.event_id().to_string()),
            event_kind: Set(payload.kind().to_string()),
            payload: Set(serde_json::to_string(&payload).unwrap()),
            status: Set(PENDING.to_string()),
            attempts: Set(0),
            available_at: Set(now),
            last_error_code: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            dead_lettered_at: Set(None),
        }
        .insert(&database)
        .await
        .unwrap();

        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database.clone(), receiver);
        assert!(actor.drain_available().await.unwrap());
        assert_eq!(
            login_events::Entity::find().count(&database).await.unwrap(),
            1
        );
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn migration_rejects_duplicate_pending_kind_and_event_id() {
        let database = database().await;
        let now = chrono::Utc::now().naive_utc();
        let row = |id: &str| audit_outbox::ActiveModel {
            id: Set(id.to_string()),
            event_id: Set("same-event".to_string()),
            event_kind: Set("login".to_string()),
            payload: Set("{}".to_string()),
            status: Set(PENDING.to_string()),
            attempts: Set(0),
            available_at: Set(now),
            last_error_code: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            dead_lettered_at: Set(None),
        };
        row("first").insert(&database).await.unwrap();
        assert!(row("second").insert(&database).await.is_err());
    }

    #[tokio::test]
    async fn all_four_event_kinds_are_durable_before_delivery() {
        let database = database().await;
        let user = user(&database, "audit-kinds@example.test").await;
        let organization = crate::store::organizations::OrganizationStore::create(
            crate::db::DB::Conn(&database),
            "audit-kinds",
            "Audit Kinds",
            &user.id,
            None,
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let handle = AuditHandle {
            sender,
            db: database.clone(),
        };
        handle
            .log_login(login_event("kinds-login", &user.id))
            .await
            .unwrap();
        handle
            .log_org(organization_audit_log::ActiveModel {
                id: Set("kinds-org".to_string()),
                org_id: Set(organization.id.clone()),
                actor_user_id: Set(user.id.clone()),
                action: Set("settings_updated".to_string()),
                target_type: Set("organization".to_string()),
                target_id: Set(organization.id),
                success: Set(true),
                ..Default::default()
            })
            .await
            .unwrap();
        handle
            .log_mfa(mfa_audit_log::ActiveModel {
                id: Set("kinds-mfa".to_string()),
                user_id: Set(user.id.clone()),
                event_type: Set("mfa_enabled".to_string()),
                success: Set(true),
                ..Default::default()
            })
            .await
            .unwrap();
        handle
            .log_platform(platform_audit_log::ActiveModel {
                id: Set("kinds-platform".to_string()),
                platform_owner_id: Set(user.id.clone()),
                action: Set("user.impersonate".to_string()),
                target_type: Set("user".to_string()),
                target_id: Set(user.id.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            4
        );
        assert_eq!(
            login_events::Entity::find().count(&database).await.unwrap(),
            0
        );
        assert_eq!(
            organization_audit_log::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            mfa_audit_log::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            platform_audit_log::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            0
        );

        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database.clone(), receiver);
        assert!(actor.drain_available().await.unwrap());
        assert_eq!(
            audit_outbox::Entity::find().count(&database).await.unwrap(),
            0
        );
        assert_eq!(
            login_events::Entity::find().count(&database).await.unwrap(),
            1
        );
        assert_eq!(
            organization_audit_log::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            mfa_audit_log::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            platform_audit_log::Entity::find()
                .count(&database)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn retry_attempts_are_bounded_and_become_observable_dead_letter() {
        let database = database().await;
        let now = chrono::Utc::now().naive_utc();
        audit_outbox::ActiveModel {
            id: Set("retry-outbox".to_string()),
            event_id: Set("retry-event".to_string()),
            event_kind: Set("login".to_string()),
            payload: Set("{}".to_string()),
            status: Set(PENDING.to_string()),
            attempts: Set(0),
            available_at: Set(now),
            last_error_code: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            dead_lettered_at: Set(None),
        }
        .insert(&database)
        .await
        .unwrap();
        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database.clone(), receiver);
        for expected_attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            let row = audit_outbox::Entity::find_by_id("retry-outbox")
                .one(&database)
                .await
                .unwrap()
                .unwrap();
            assert!(actor.record_failure(&row, "database_error").await);
            let updated = audit_outbox::Entity::find_by_id("retry-outbox")
                .one(&database)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(updated.attempts, expected_attempt);
        }
        let dead = audit_outbox::Entity::find_by_id("retry-outbox")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dead.status, DEAD_LETTER);
        assert_eq!(dead.last_error_code.as_deref(), Some("database_error"));
        assert!(dead.dead_lettered_at.is_some());
    }

    #[tokio::test]
    async fn each_wake_is_bounded_and_leaves_remaining_rows_durable() {
        let database = database().await;
        let now = chrono::Utc::now().naive_utc();
        let total = DELIVERY_BATCH_SIZE as usize * MAX_BATCHES_PER_WAKE + 1;
        for index in 0..total {
            audit_outbox::ActiveModel {
                id: Set(format!("bounded-outbox-{index:03}")),
                event_id: Set(format!("bounded-event-{index:03}")),
                event_kind: Set("login".to_string()),
                payload: Set("invalid-json".to_string()),
                status: Set(PENDING.to_string()),
                attempts: Set(0),
                available_at: Set(now),
                last_error_code: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
                dead_lettered_at: Set(None),
            }
            .insert(&database)
            .await
            .unwrap();
        }
        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database.clone(), receiver);
        assert!(!actor.drain_available().await.unwrap());
        assert_eq!(
            audit_outbox::Entity::find()
                .filter(audit_outbox::Column::Status.eq(PENDING))
                .count(&database)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn failed_failure_state_write_stops_delivery_instead_of_spinning() {
        let database = database().await;
        let now = chrono::Utc::now().naive_utc();
        let row = audit_outbox::Model {
            id: "missing-outbox".to_string(),
            event_id: "missing-event".to_string(),
            event_kind: "login".to_string(),
            payload: "invalid-json".to_string(),
            status: PENDING.to_string(),
            attempts: 0,
            available_at: now,
            last_error_code: None,
            created_at: now,
            updated_at: now,
            dead_lettered_at: None,
        };
        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database, receiver);
        assert!(!actor.deliver(row).await);
    }

    #[test]
    fn qualified_concurrency_constraint_is_explicit() {
        assert_eq!(
            RECONCILER_CONCURRENCY,
            "single worker per database is the qualified topology"
        );
    }

    #[tokio::test]
    async fn invalid_payload_moves_to_observable_redacted_dead_letter() {
        let database = database().await;
        let now = chrono::Utc::now().naive_utc();
        audit_outbox::ActiveModel {
            id: Set("bad-outbox".to_string()),
            event_id: Set("bad-event".to_string()),
            event_kind: Set("login".to_string()),
            payload: Set("audit-secret-not-json".to_string()),
            status: Set(PENDING.to_string()),
            attempts: Set(0),
            available_at: Set(now),
            last_error_code: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            dead_lettered_at: Set(None),
        }
        .insert(&database)
        .await
        .unwrap();
        let (_sender, receiver) = mpsc::channel(1);
        let actor = AuditActor::new(database.clone(), receiver);
        assert!(actor.drain_available().await.unwrap());
        let row = audit_outbox::Entity::find_by_id("bad-outbox")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, DEAD_LETTER);
        assert_eq!(row.last_error_code.as_deref(), Some("invalid_payload"));
        assert!(row.dead_lettered_at.is_some());
        assert!(!row.last_error_code.unwrap().contains("audit-secret"));
    }
}
