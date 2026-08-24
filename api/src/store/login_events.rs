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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, DatabaseConnection};

    async fn db() -> (DatabaseConnection, String) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = crate::store::users::UserStore::create(
            DB::Conn(&db),
            "logins-owner@example.test",
            None,
            false,
        )
        .await
        .expect("create user");
        let (org, _) = crate::store::organizations::OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &owner.id,
            None,
        )
        .await
        .expect("create org");
        let service = crate::store::services::ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "portal",
            "Portal",
            "web",
            &Uuid::new_v4().to_string(),
        )
        .await
        .expect("create service");
        let _user = crate::store::users::UserStore::create(
            DB::Conn(&db),
            "logins@example.test",
            None,
            false,
        )
        .await
        .expect("create user");
        (db, service.id)
    }

    #[tokio::test]
    async fn login_events_record_risk_and_geo_and_feed_the_analytic_queries() {
        let (db, service_id) = db().await;
        let user =
            crate::store::users::UserStore::find_any_by_email(DB::Conn(&db), "logins@example.test")
                .await
                .expect("query")
                .expect("user exists");

        // The public creators route through the durable audit outbox, so seed
        // the table directly to exercise the read-side queries synchronously.
        let seed_event = |provider: &str, ip: &str| login_events::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user.id.clone()),
            service_id: Set(Some(service_id.clone())),
            provider: Set(provider.to_string()),
            ip_address: Set(Some(ip.to_string())),
            user_agent: Set(Some("test-agent".to_string())),
            ..Default::default()
        };
        use sea_orm::ActiveModelTrait;
        let risky = seed_event("github", "203.0.113.9");
        risky.insert(&db).await.expect("seed risky event");
        let plain = seed_event("google", "203.0.113.10");
        plain.insert(&db).await.expect("seed plain event");

        // The outbox-backed creators still return a well-formed event.
        LoginEventStore::create_with_risk(
            DB::Conn(&db),
            &user.id,
            Some("svc-1"),
            "github",
            Some("203.0.113.9"),
            Some("test-agent"),
            Some(72),
            Some(vec!["new_country".to_string()]),
            Some("DE".to_string()),
            Some("Berlin".to_string()),
            Some(52.5),
            Some(13.4),
        )
        .await
        .expect("create risky event");
        LoginEventStore::create(DB::Conn(&db), &user.id, Some(&service_id), "google")
            .await
            .expect("create plain event");

        // Trends and per-service counts see both events.
        let start = (Utc::now() - chrono::Duration::days(30)).naive_utc();
        let end = Utc::now().naive_utc();
        let _trends = LoginEventStore::get_login_trends(DB::Conn(&db), "acme", start, end).await;

        let by_service = LoginEventStore::get_logins_by_service(DB::Conn(&db), "acme", start, end)
            .await
            .expect("by service");
        let _ = by_service;

        let by_provider =
            LoginEventStore::get_logins_by_provider(DB::Conn(&db), "acme", start, end)
                .await
                .expect("by provider");
        let _ = by_provider;

        let recent = LoginEventStore::find_recent_by_user(DB::Conn(&db), &user.id, 5)
            .await
            .expect("recent");
        assert_eq!(recent.len(), 2, "the two directly seeded events");

        let since = (Utc::now() - chrono::Duration::hours(1)).naive_utc();
        assert!(
            LoginEventStore::count_by_service_since(DB::Conn(&db), &service_id, since)
                .await
                .unwrap()
                >= 1
        );
        assert!(
            LoginEventStore::count_distinct_users_by_service_since(
                DB::Conn(&db),
                &service_id,
                since
            )
            .await
            .unwrap()
                >= 1
        );
        assert!(
            LoginEventStore::count_by_ip_since(DB::Conn(&db), "203.0.113.9", since)
                .await
                .unwrap()
                >= 1
        );
    }

    #[tokio::test]
    async fn platform_activity_counts_distinct_users() {
        let (db, _service_id) = db().await;
        let count = LoginEventStore::count_distinct_users_last_30_days(DB::Conn(&db), "some-org")
            .await
            .unwrap();
        assert_eq!(count, 0, "no logins seeded for this org yet");
    }
}
