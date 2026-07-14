use crate::entities::login_events;
use crate::entities::prelude::LoginEvents;
use crate::entities::services;
use crate::error::Result;
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::sea_query::{Alias, Expr, SimpleExpr};
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, FromQueryResult, JoinType, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Set,
};
use serde::Serialize;
use uuid::Uuid;

/// Login trend data point (date, count)
#[derive(Debug, FromQueryResult, Serialize)]
pub struct LoginTrendPoint {
    pub date: Option<String>,
    pub count: i64,
}

/// Logins grouped by service
#[derive(Debug, FromQueryResult, Serialize)]
pub struct LoginsByService {
    pub service_id: String,
    pub service_name: String,
    pub count: i64,
}

/// Logins grouped by provider
#[derive(Debug, FromQueryResult, Serialize)]
pub struct LoginsByProvider {
    pub provider: String,
    pub count: i64,
}

/// Recent login data
#[derive(Debug, FromQueryResult, Serialize)]
pub struct RecentLogin {
    pub id: String,
    pub user_id: String,
    pub service_id: Option<String>,
    pub provider: String,
    pub created_at: String,
}

pub struct LoginEventStore;

/// Select events that are unambiguously attributable to a tenant. Newer
/// events carry `org_id` directly, while legacy service logins may only carry
/// `service_id`. If both are present they must agree, so corrupt or stale
/// cross-tenant pairs cannot leak through either side of the fallback.
pub(crate) fn tenant_login_scope(org_id: &str) -> Condition {
    Condition::any()
        .add(
            Condition::all()
                .add(login_events::Column::OrgId.eq(org_id))
                .add(login_events::Column::ServiceId.is_null()),
        )
        .add(
            Condition::all()
                .add(services::Column::OrgId.eq(org_id))
                .add(
                    Condition::any()
                        .add(login_events::Column::OrgId.is_null())
                        .add(login_events::Column::OrgId.eq(org_id)),
                ),
        )
}

impl LoginEventStore {
    /// Create a new login event
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        service_id: Option<&str>,
        provider: &str,
    ) -> Result<login_events::Model> {
        let new_event = login_events::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.map(|s| s.to_string())),
            provider: Set(provider.to_string()),
            ..Default::default()
        };

        crate::services::audit_actor::enqueue_login_with_connection(&db, new_event).await
    }

    /// Create a new login event with risk assessment data and optional geo data
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_risk(
        db: DB<'_>,
        user_id: &str,
        service_id: Option<&str>,
        provider: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        risk_score: Option<i32>,
        risk_factors: Option<Vec<String>>,
        geo_country: Option<String>,
        geo_city: Option<String>,
        geo_lat: Option<f64>,
        geo_long: Option<f64>,
    ) -> Result<login_events::Model> {
        let risk_factors_json =
            risk_factors.map(|factors| serde_json::to_string(&factors).unwrap_or_default());

        let new_event = login_events::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.map(|s| s.to_string())),
            provider: Set(provider.to_string()),
            ip_address: Set(ip_address.map(|s| s.to_string())),
            user_agent: Set(user_agent.map(|s| s.to_string())),
            risk_score: Set(risk_score),
            risk_factors: Set(risk_factors_json),
            geo_country: Set(geo_country),
            geo_city: Set(geo_city),
            geo_lat: Set(geo_lat),
            geo_long: Set(geo_long),
            ..Default::default()
        };

        crate::services::audit_actor::enqueue_login_with_connection(&db, new_event).await
    }

    /// Get login trends grouped by date for an organization
    pub async fn get_login_trends(
        db: DB<'_>,
        org_id: &str,
        start_date: NaiveDateTime,
        end_date: NaiveDateTime,
    ) -> Result<Vec<LoginTrendPoint>> {
        // Use DATE() function - works in SQLite, MySQL, PostgreSQL
        // DATE() returns text string in YYYY-MM-DD format across all databases
        let date_expr: SimpleExpr =
            Expr::cust_with_expr("DATE($1)", Expr::col(login_events::Column::CreatedAt));

        let trends = LoginEvents::find()
            .join(JoinType::LeftJoin, login_events::Relation::Services.def())
            .filter(tenant_login_scope(org_id))
            .filter(login_events::Column::CreatedAt.gte(start_date))
            .filter(login_events::Column::CreatedAt.lte(end_date))
            .select_only()
            .column_as(date_expr.clone(), "date")
            .column_as(
                Expr::col((login_events::Entity, login_events::Column::Id)).count(),
                "count",
            )
            .group_by(date_expr)
            .order_by_asc(Expr::col(Alias::new("date")))
            .into_model::<LoginTrendPoint>()
            .all(&db)
            .await?;

        Ok(trends)
    }

    /// Get logins grouped by service for an organization
    pub async fn get_logins_by_service(
        db: DB<'_>,
        org_id: &str,
        start_date: NaiveDateTime,
        end_date: NaiveDateTime,
    ) -> Result<Vec<LoginsByService>> {
        let logins = LoginEvents::find()
            .join(JoinType::InnerJoin, login_events::Relation::Services.def())
            .filter(services::Column::OrgId.eq(org_id))
            .filter(
                Condition::any()
                    .add(login_events::Column::OrgId.is_null())
                    .add(login_events::Column::OrgId.eq(org_id)),
            )
            .filter(login_events::Column::CreatedAt.gte(start_date))
            .filter(login_events::Column::CreatedAt.lte(end_date))
            .select_only()
            .column_as(services::Column::Id, "service_id")
            .column_as(services::Column::Name, "service_name")
            .column_as(
                Expr::col((login_events::Entity, login_events::Column::Id)).count(),
                "count",
            )
            .group_by(services::Column::Id)
            .group_by(services::Column::Name)
            .order_by_desc(Expr::col(sea_orm::sea_query::Alias::new("count")))
            .into_model::<LoginsByService>()
            .all(&db)
            .await?;

        Ok(logins)
    }

    /// Get logins grouped by provider for an organization
    pub async fn get_logins_by_provider(
        db: DB<'_>,
        org_id: &str,
        start_date: NaiveDateTime,
        end_date: NaiveDateTime,
    ) -> Result<Vec<LoginsByProvider>> {
        let logins = LoginEvents::find()
            .join(JoinType::LeftJoin, login_events::Relation::Services.def())
            .filter(tenant_login_scope(org_id))
            .filter(login_events::Column::CreatedAt.gte(start_date))
            .filter(login_events::Column::CreatedAt.lte(end_date))
            .select_only()
            .column(login_events::Column::Provider)
            .column_as(
                Expr::col((login_events::Entity, login_events::Column::Id)).count(),
                "count",
            )
            .group_by(login_events::Column::Provider)
            .order_by_desc(Expr::col(sea_orm::sea_query::Alias::new("count")))
            .into_model::<LoginsByProvider>()
            .all(&db)
            .await?;

        Ok(logins)
    }

    /// Get recent logins for an organization
    pub async fn get_recent_logins(
        db: DB<'_>,
        org_id: &str,
        limit: i64,
    ) -> Result<Vec<RecentLogin>> {
        // Keep this store boundary safe even when called outside the HTTP
        // handler: never cast a negative signed limit into an enormous u64.
        let (limit, _) = crate::utils::pagination::store_u64(limit, 0, 100);
        let logins = LoginEvents::find()
            .join(JoinType::LeftJoin, login_events::Relation::Services.def())
            .filter(tenant_login_scope(org_id))
            .order_by_desc(login_events::Column::CreatedAt)
            .limit(limit)
            .select_only()
            .column_as(login_events::Column::Id, "id")
            .column_as(login_events::Column::UserId, "user_id")
            .column_as(login_events::Column::ServiceId, "service_id")
            .column_as(login_events::Column::Provider, "provider")
            .column_as(login_events::Column::CreatedAt, "created_at")
            .into_model::<RecentLogin>()
            .all(&db)
            .await?;

        Ok(logins)
    }

    /// Count login events for a service in a time period
    pub async fn count_by_service_since(
        db: DB<'_>,
        service_id: &str,
        since: NaiveDateTime,
    ) -> Result<i64> {
        let count = LoginEvents::find()
            .filter(login_events::Column::ServiceId.eq(service_id))
            .filter(login_events::Column::CreatedAt.gte(since))
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// Count distinct users for a service in a time period
    pub async fn count_distinct_users_by_service_since(
        db: DB<'_>,
        service_id: &str,
        since: NaiveDateTime,
    ) -> Result<i64> {
        let count = LoginEvents::find()
            .filter(login_events::Column::ServiceId.eq(service_id))
            .filter(login_events::Column::CreatedAt.gte(since))
            .select_only()
            .column(login_events::Column::UserId)
            .distinct()
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// Count platform-wide login events in a time period (24 hours, 30 days, etc.)
    pub async fn count_since(db: DB<'_>, since_datetime: NaiveDateTime) -> Result<i64> {
        let count = LoginEvents::find()
            .filter(login_events::Column::CreatedAt.gte(since_datetime))
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// Get platform-wide login activity trends by date
    pub async fn get_platform_activity_trends(
        db: DB<'_>,
        start_date: NaiveDateTime,
        end_date: NaiveDateTime,
    ) -> Result<Vec<LoginTrendPoint>> {
        // Use DATE() function - works in SQLite, MySQL, PostgreSQL
        let date_expr: SimpleExpr =
            Expr::cust_with_expr("DATE($1)", Expr::col(login_events::Column::CreatedAt));

        let trends = LoginEvents::find()
            .filter(login_events::Column::CreatedAt.gte(start_date))
            .filter(login_events::Column::CreatedAt.lte(end_date))
            .select_only()
            .column_as(date_expr.clone(), "date")
            .column_as(Expr::col(login_events::Column::Id).count(), "count")
            .group_by(date_expr)
            .order_by_asc(Expr::col(Alias::new("date")))
            .into_model::<LoginTrendPoint>()
            .all(&db)
            .await?;

        Ok(trends)
    }

    /// Find recent login events for a specific user (for impossible travel detection)
    pub async fn find_recent_by_user(
        db: DB<'_>,
        user_id: &str,
        limit: i64,
    ) -> Result<Vec<login_events::Model>> {
        use sea_orm::{Order, QueryOrder, QuerySelect};

        let (limit, _) = crate::utils::pagination::store_u64(limit, 0, 100);
        let events = LoginEvents::find()
            .filter(login_events::Column::UserId.eq(user_id))
            .order_by(login_events::Column::CreatedAt, Order::Desc)
            .limit(limit)
            .all(&db)
            .await?;

        Ok(events)
    }

    /// Count login events from a specific IP since a given time (for velocity checks)
    pub async fn count_by_ip_since(db: DB<'_>, ip: &str, since: NaiveDateTime) -> Result<i64> {
        let count = LoginEvents::find()
            .filter(login_events::Column::IpAddress.eq(ip))
            .filter(login_events::Column::CreatedAt.gte(since))
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// Count distinct users who logged in within the last 30 days for an organization (MAU)
    /// This is used for tier enforcement and billing calculations
    pub async fn count_distinct_users_last_30_days(db: DB<'_>, org_id: &str) -> Result<i64> {
        let thirty_days_ago = chrono::Utc::now().naive_utc() - chrono::Duration::days(30);

        let count = LoginEvents::find()
            .join(JoinType::LeftJoin, login_events::Relation::Services.def())
            .filter(tenant_login_scope(org_id))
            .filter(login_events::Column::CreatedAt.gte(thirty_days_ago))
            .select_only()
            .column(login_events::Column::UserId)
            .distinct()
            .count(&db)
            .await?;

        Ok(count as i64)
    }
}
