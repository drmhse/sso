use crate::error::Result;
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, Set};
use std::collections::HashMap;

#[derive(Debug, Clone, FromQueryResult)]
pub struct SubscriptionWithPlan {
    pub plan_name: String,
    pub features: Option<String>,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct SubscriptionQueryResult {
    pub service_slug: String,
    pub plan_name: String,
    pub features: Option<String>,
    pub status: String,
    pub current_period_end: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct ServiceWithSubscription {
    pub service_id: String,
    pub service_slug: String,
    pub org_slug: String,
    pub plan_name: Option<String>,
    pub features: Option<String>,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct SubscriptionWithDetails {
    pub service_id: String,
    pub service_slug: String,
    pub service_name: String,
    pub plan_id: String,
    pub plan_name: String,
    pub status: String,
    pub current_period_end: String,
    pub created_at: String,
}

/// End-user data for organization customer management
#[derive(Debug, Clone, FromQueryResult)]
pub struct EndUser {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub created_at: String,
}

/// Subscription details for end-user management
#[derive(Debug, Clone, FromQueryResult)]
pub struct EndUserSubscriptionRow {
    pub user_id: String,
    pub service_id: String,
    pub service_slug: String,
    pub service_name: String,
    pub plan_id: String,
    pub plan_name: String,
    pub status: String,
    pub current_period_end: String,
    pub subscription_created_at: String,
}

/// Subscription with plan details for service API
#[derive(Debug, Clone, FromQueryResult, serde::Serialize)]
pub struct SubscriptionWithPlanDetails {
    pub id: String,
    pub user_id: String,
    pub plan_id: String,
    pub status: String,
    pub current_period_end: String,
    pub plan_name: String,
}

#[derive(Debug, FromQueryResult)]
struct CountByService {
    service_id: String,
    count: i64,
}

#[derive(Debug, FromQueryResult)]
struct CountByPlan {
    plan_id: String,
    count: i64,
}

pub struct SubscriptionStore;

impl SubscriptionStore {
    /// Get subscription info by user, org_slug, and service_slug
    pub async fn get_subscription_by_user_org_service(
        db: DB<'_>,
        user_id: &str,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<Option<SubscriptionQueryResult>> {
        use crate::entities::{organizations, plans, services, subscriptions};
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        let result = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .join(JoinType::InnerJoin, subscriptions::Relation::Plans.def())
            .join(JoinType::InnerJoin, services::Relation::Organizations.def())
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(organizations::Column::Slug.eq(org_slug))
            .filter(services::Column::Slug.eq(service_slug))
            .select_only()
            .column_as(services::Column::Slug, "service_slug")
            .column_as(plans::Column::Name, "plan_name")
            .column_as(plans::Column::Features, "features")
            .column_as(subscriptions::Column::Status, "status")
            .column_as(
                subscriptions::Column::CurrentPeriodEnd,
                "current_period_end",
            )
            .into_model::<SubscriptionQueryResult>()
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Get active subscription with plan details for a user and service
    pub async fn get_active_subscription(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<Option<SubscriptionWithPlan>> {
        use crate::entities::{plans, prelude::Subscriptions, subscriptions};
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        let result = Subscriptions::find()
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(subscriptions::Column::ServiceId.eq(service_id))
            .filter(subscriptions::Column::Status.eq("active"))
            .join(JoinType::InnerJoin, subscriptions::Relation::Plans.def())
            .select_only()
            .column_as(plans::Column::Name, "plan_name")
            .column_as(plans::Column::Features, "features")
            .into_model::<SubscriptionWithPlan>()
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Get service with subscription info by organization and service slug
    /// Used for token exchange and device flows
    pub async fn get_service_with_subscription(
        db: DB<'_>,
        user_id: &str,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<Option<ServiceWithSubscription>> {
        use crate::entities::{organizations, plans, services, subscriptions};
        use sea_orm::sea_query::Expr;
        use sea_orm::{Condition, JoinType, QuerySelect, RelationTrait};

        // Build custom join condition for subscriptions: sub.service_id = s.id AND sub.user_id = ?
        let sub_join_condition = Condition::all()
            .add(
                Expr::col((subscriptions::Entity, subscriptions::Column::ServiceId))
                    .equals((services::Entity, services::Column::Id)),
            )
            .add(subscriptions::Column::UserId.eq(user_id));

        let result = services::Entity::find()
            .join(JoinType::InnerJoin, services::Relation::Organizations.def())
            .join_as(
                JoinType::LeftJoin,
                services::Relation::Subscriptions
                    .def()
                    .on_condition(move |_left, _right| sub_join_condition.clone()),
                subscriptions::Entity,
            )
            .join(JoinType::LeftJoin, subscriptions::Relation::Plans.def())
            .filter(organizations::Column::Slug.eq(org_slug))
            .filter(services::Column::Slug.eq(service_slug))
            .select_only()
            .column_as(services::Column::Id, "service_id")
            .column_as(services::Column::Slug, "service_slug")
            .column_as(organizations::Column::Slug, "org_slug")
            .column_as(plans::Column::Name, "plan_name")
            .column_as(plans::Column::Features, "features")
            .into_model::<ServiceWithSubscription>()
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Count subscriptions for a user in an organization
    pub async fn count_by_user_and_org(db: DB<'_>, user_id: &str, org_id: &str) -> Result<u64> {
        use crate::entities::{services, subscriptions};
        use sea_orm::{JoinType, PaginatorTrait, QueryFilter, QuerySelect, RelationTrait};

        let count = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(services::Column::OrgId.eq(org_id))
            .count(&db)
            .await?;

        Ok(count)
    }

    /// List subscriptions with details for a user in an organization
    pub async fn list_with_details_by_user_and_org(
        db: DB<'_>,
        user_id: &str,
        org_id: &str,
    ) -> Result<Vec<SubscriptionWithDetails>> {
        use crate::entities::{plans, services, subscriptions};
        use sea_orm::{JoinType, QueryOrder, QuerySelect, RelationTrait};

        let results = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .join(JoinType::InnerJoin, subscriptions::Relation::Plans.def())
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(services::Column::OrgId.eq(org_id))
            .order_by_desc(subscriptions::Column::CreatedAt)
            .select_only()
            .column(subscriptions::Column::ServiceId)
            .column_as(services::Column::Slug, "service_slug")
            .column_as(services::Column::Name, "service_name")
            .column(subscriptions::Column::PlanId)
            .column_as(plans::Column::Name, "plan_name")
            .column(subscriptions::Column::Status)
            .column(subscriptions::Column::CurrentPeriodEnd)
            .column(subscriptions::Column::CreatedAt)
            .into_model::<SubscriptionWithDetails>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// List end-users (users with subscriptions/identities) for an organization
    /// Optionally filtered by service
    pub async fn list_end_users_by_org(
        db: DB<'_>,
        org_id: &str,
        service_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<EndUser>> {
        use crate::entities::{identities, services, subscriptions, users};
        use sea_orm::sea_query::{Expr, Query};
        use sea_orm::{Condition, Order, QueryFilter, QueryOrder, QuerySelect};

        let mut identity_exists = Query::select();
        identity_exists
            .expr(Expr::val(1))
            .from(identities::Entity)
            .and_where(
                Expr::col((identities::Entity, identities::Column::UserId))
                    .equals((users::Entity, users::Column::Id)),
            )
            .and_where(Expr::col(identities::Column::IssuingOrgId).eq(org_id));

        let mut subscription_exists = Query::select();
        subscription_exists
            .expr(Expr::val(1))
            .from(subscriptions::Entity)
            .and_where(
                Expr::col((subscriptions::Entity, subscriptions::Column::UserId))
                    .equals((users::Entity, users::Column::Id)),
            );

        if let Some(svc_id) = service_id {
            identity_exists.and_where(Expr::col(identities::Column::IssuingServiceId).eq(svc_id));
            subscription_exists.and_where(Expr::col(subscriptions::Column::ServiceId).eq(svc_id));
        } else {
            subscription_exists
                .inner_join(
                    services::Entity,
                    Expr::col((subscriptions::Entity, subscriptions::Column::ServiceId))
                        .equals((services::Entity, services::Column::Id)),
                )
                .and_where(Expr::col(services::Column::OrgId).eq(org_id));
        }

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        let results = users::Entity::find()
            .filter(
                Condition::any()
                    .add(Expr::exists(identity_exists.to_owned()))
                    .add(Expr::exists(subscription_exists.to_owned())),
            )
            .order_by(users::Column::CreatedAt, Order::Desc)
            .limit(limit)
            .offset(offset)
            .select_only()
            .column_as(users::Column::Id, "id")
            .column_as(users::Column::Email, "email")
            .column_as(users::Column::IsPlatformOwner, "is_platform_owner")
            .column_as(users::Column::CreatedAt, "created_at")
            .into_model::<EndUser>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Count end-users for an organization (optionally by service)
    pub async fn count_end_users_by_org(
        db: DB<'_>,
        org_id: &str,
        service_id: Option<&str>,
    ) -> Result<i64> {
        use crate::entities::{identities, services, subscriptions, users};
        use sea_orm::sea_query::{Expr, Query};
        use sea_orm::{Condition, PaginatorTrait, QueryFilter};

        let mut identity_exists = Query::select();
        identity_exists
            .expr(Expr::val(1))
            .from(identities::Entity)
            .and_where(
                Expr::col((identities::Entity, identities::Column::UserId))
                    .equals((users::Entity, users::Column::Id)),
            )
            .and_where(Expr::col(identities::Column::IssuingOrgId).eq(org_id));

        let mut subscription_exists = Query::select();
        subscription_exists
            .expr(Expr::val(1))
            .from(subscriptions::Entity)
            .and_where(
                Expr::col((subscriptions::Entity, subscriptions::Column::UserId))
                    .equals((users::Entity, users::Column::Id)),
            );

        if let Some(svc_id) = service_id {
            identity_exists.and_where(Expr::col(identities::Column::IssuingServiceId).eq(svc_id));
            subscription_exists.and_where(Expr::col(subscriptions::Column::ServiceId).eq(svc_id));
        } else {
            subscription_exists
                .inner_join(
                    services::Entity,
                    Expr::col((subscriptions::Entity, subscriptions::Column::ServiceId))
                        .equals((services::Entity, services::Column::Id)),
                )
                .and_where(Expr::col(services::Column::OrgId).eq(org_id));
        }

        let count = users::Entity::find()
            .filter(
                Condition::any()
                    .add(Expr::exists(identity_exists.to_owned()))
                    .add(Expr::exists(subscription_exists.to_owned())),
            )
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// Check if a specific user is an end-user of an organization
    /// Uses the same query logic as list_end_users_by_org for consistency
    pub async fn is_end_user_of_org(db: DB<'_>, user_id: &str, org_id: &str) -> Result<bool> {
        use crate::entities::{identities, services, subscriptions};
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        // Check if user has any identity for this org
        let identity_exists = identities::Entity::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingOrgId.eq(org_id))
            .select_only()
            .column(identities::Column::Id)
            .into_tuple::<String>()
            .one(&db)
            .await?
            .is_some();

        if identity_exists {
            return Ok(true);
        }

        // Check if user has any subscription for a service in this org
        let subscription_exists = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(services::Column::OrgId.eq(org_id))
            .select_only()
            .column(subscriptions::Column::Id)
            .into_tuple::<String>()
            .one(&db)
            .await?
            .is_some();

        Ok(subscription_exists)
    }

    /// List subscriptions for multiple users in an organization (for end-user management)
    /// Returns subscriptions with service and plan details
    pub async fn list_subscriptions_for_users_in_org(
        db: DB<'_>,
        user_ids: &[String],
        org_id: &str,
        service_id: Option<&str>,
    ) -> Result<Vec<EndUserSubscriptionRow>> {
        use crate::entities::{plans, services, subscriptions};
        use sea_orm::{JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait};

        if user_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut query = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .join(JoinType::InnerJoin, subscriptions::Relation::Plans.def())
            .filter(subscriptions::Column::UserId.is_in(user_ids));

        if let Some(svc_id) = service_id {
            query = query.filter(subscriptions::Column::ServiceId.eq(svc_id));
        } else {
            query = query.filter(services::Column::OrgId.eq(org_id));
        }

        let results = query
            .order_by_desc(subscriptions::Column::CreatedAt)
            .select_only()
            .column(subscriptions::Column::UserId)
            .column(subscriptions::Column::ServiceId)
            .column_as(services::Column::Slug, "service_slug")
            .column_as(services::Column::Name, "service_name")
            .column(subscriptions::Column::PlanId)
            .column_as(plans::Column::Name, "plan_name")
            .column(subscriptions::Column::Status)
            .column(subscriptions::Column::CurrentPeriodEnd)
            .column_as(subscriptions::Column::CreatedAt, "subscription_created_at")
            .into_model::<EndUserSubscriptionRow>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Count active subscriptions for a service
    pub async fn count_active_by_service(db: DB<'_>, service_id: &str) -> Result<i64> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;
        use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

        let count = Subscriptions::find()
            .filter(subscriptions::Column::ServiceId.eq(service_id))
            .filter(subscriptions::Column::Status.eq("active"))
            .count(&db)
            .await? as i64;

        Ok(count)
    }

    /// Count active subscriptions grouped by service ID.
    pub async fn count_active_by_services(
        db: DB<'_>,
        service_ids: &[String],
    ) -> Result<HashMap<String, i64>> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};

        if service_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = Subscriptions::find()
            .filter(subscriptions::Column::ServiceId.is_in(service_ids.iter().cloned()))
            .filter(subscriptions::Column::Status.eq("active"))
            .select_only()
            .column(subscriptions::Column::ServiceId)
            .column_as(subscriptions::Column::Id.count(), "count")
            .group_by(subscriptions::Column::ServiceId)
            .into_model::<CountByService>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.service_id, row.count))
            .collect())
    }

    /// Count active subscriptions for a plan
    pub async fn count_active_by_plan(db: DB<'_>, plan_id: &str) -> Result<i64> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;
        use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

        let count = Subscriptions::find()
            .filter(subscriptions::Column::PlanId.eq(plan_id))
            .filter(subscriptions::Column::Status.eq("active"))
            .count(&db)
            .await? as i64;

        Ok(count)
    }

    /// Count active subscriptions grouped by plan ID.
    pub async fn count_active_by_plans(
        db: DB<'_>,
        plan_ids: &[String],
    ) -> Result<HashMap<String, i64>> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};

        if plan_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = Subscriptions::find()
            .filter(subscriptions::Column::PlanId.is_in(plan_ids.iter().cloned()))
            .filter(subscriptions::Column::Status.eq("active"))
            .select_only()
            .column(subscriptions::Column::PlanId)
            .column_as(subscriptions::Column::Id.count(), "count")
            .group_by(subscriptions::Column::PlanId)
            .into_model::<CountByPlan>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.plan_id, row.count))
            .collect())
    }

    /// Count active subscriptions for a service by organization and slug lookup
    pub async fn count_active_by_service_lookup(
        db: DB<'_>,
        org_id: &str,
        service_slug: &str,
    ) -> Result<i64> {
        use crate::store::services::ServiceStore;

        // First find the service
        let service = ServiceStore::find_by_org_and_slug(db.clone(), org_id, service_slug).await?;

        if let Some(svc) = service {
            // Then count subscriptions for that service
            Self::count_active_by_service(db, &svc.id).await
        } else {
            Ok(0)
        }
    }

    /// Count subscriptions for a service with optional status filter
    pub async fn count_by_service_with_status(
        db: DB<'_>,
        service_id: &str,
        status: Option<&str>,
    ) -> Result<i64> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;
        use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

        let mut query =
            Subscriptions::find().filter(subscriptions::Column::ServiceId.eq(service_id));

        if let Some(s) = status {
            query = query.filter(subscriptions::Column::Status.eq(s));
        }

        let count = query.count(&db).await? as i64;
        Ok(count)
    }

    /// List subscriptions with plan details for a service (with optional status filter and pagination)
    pub async fn list_by_service_with_plan_details(
        db: DB<'_>,
        service_id: &str,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SubscriptionWithPlanDetails>> {
        use crate::entities::{plans, subscriptions};
        use sea_orm::{
            ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
        };

        let mut query = crate::entities::prelude::Subscriptions::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Plans.def())
            .filter(subscriptions::Column::ServiceId.eq(service_id))
            .select_only()
            .column(subscriptions::Column::Id)
            .column(subscriptions::Column::UserId)
            .column(subscriptions::Column::PlanId)
            .column(subscriptions::Column::Status)
            .column(subscriptions::Column::CurrentPeriodEnd)
            .column_as(plans::Column::Name, "plan_name")
            .order_by_desc(subscriptions::Column::CurrentPeriodEnd);

        if let Some(s) = status {
            query = query.filter(subscriptions::Column::Status.eq(s));
        }

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        let results = query
            .limit(limit)
            .offset(offset)
            .into_model::<SubscriptionWithPlanDetails>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Get subscription for a specific user and service
    pub async fn get_by_user_and_service(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<Option<SubscriptionWithPlanDetails>> {
        use crate::entities::{plans, subscriptions};
        use sea_orm::{
            ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
        };

        let result = crate::entities::prelude::Subscriptions::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Plans.def())
            .filter(subscriptions::Column::ServiceId.eq(service_id))
            .filter(subscriptions::Column::UserId.eq(user_id))
            .select_only()
            .column(subscriptions::Column::Id)
            .column(subscriptions::Column::UserId)
            .column(subscriptions::Column::PlanId)
            .column(subscriptions::Column::Status)
            .column(subscriptions::Column::CurrentPeriodEnd)
            .column_as(plans::Column::Name, "plan_name")
            .order_by_desc(subscriptions::Column::CurrentPeriodEnd)
            .into_model::<SubscriptionWithPlanDetails>()
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Count all subscriptions for a service (no filter)
    pub async fn count_by_service(db: DB<'_>, service_id: &str) -> Result<i64> {
        Self::count_by_service_with_status(db, service_id, None).await
    }

    /// Create a new subscription
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        plan_id: &str,
        status: &str,
        current_period_end: NaiveDateTime,
    ) -> Result<crate::entities::subscriptions::Model> {
        use crate::entities::subscriptions;
        use uuid::Uuid;

        let new_subscription = subscriptions::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.to_string()),
            plan_id: Set(plan_id.to_string()),
            status: Set(status.to_string()),
            current_period_end: Set(current_period_end),
            created_at: Set(chrono::Utc::now().naive_utc()),
        };

        let subscription = new_subscription.insert(&db).await?;
        Ok(subscription)
    }

    /// Update subscription status and period end
    pub async fn update(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        status: Option<&str>,
        current_period_end: Option<NaiveDateTime>,
    ) -> Result<crate::entities::subscriptions::Model> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;

        // Find the subscription first
        let subscription = Subscriptions::find()
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(subscriptions::Column::ServiceId.eq(service_id))
            .one(&db)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::NotFound(
                    "Subscription not found for this user and service".to_string(),
                )
            })?;

        let mut subscription_active: subscriptions::ActiveModel = subscription.into();

        if let Some(s) = status {
            subscription_active.status = Set(s.to_string());
        }

        if let Some(period_end) = current_period_end {
            subscription_active.current_period_end = Set(period_end);
        }

        let updated_subscription = subscription_active.update(&db).await?;
        Ok(updated_subscription)
    }

    /// Delete a subscription for a specific user and service
    pub async fn delete(db: DB<'_>, user_id: &str, service_id: &str) -> Result<()> {
        use crate::entities::prelude::Subscriptions;
        use crate::entities::subscriptions;

        let subscription = Subscriptions::find()
            .filter(subscriptions::Column::UserId.eq(user_id))
            .filter(subscriptions::Column::ServiceId.eq(service_id))
            .one(&db)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::NotFound(
                    "Subscription not found for this user and service".to_string(),
                )
            })?;

        let subscription_active: subscriptions::ActiveModel = subscription.into();
        subscription_active.delete(&db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::identities::IdentityStore;
    use crate::store::organizations::OrganizationStore;
    use crate::store::plans::PlanStore;
    use crate::store::services::ServiceStore;
    use crate::store::users::{UserCreationOptions, UserStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::collections::HashSet;

    #[tokio::test]
    async fn end_user_listing_uses_identity_and_subscription_matches() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org = OrganizationStore::create(DB::Conn(&db), "acme", "Acme", &owner.id, None)
            .await
            .expect("create org");
        let service_a = ServiceStore::create_with_options(
            DB::Conn(&db),
            "svc-a",
            &org.id,
            "app-a",
            "App A",
            "web",
            "client-a",
            "secret-a",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create service a");
        let service_b = ServiceStore::create_with_options(
            DB::Conn(&db),
            "svc-b",
            &org.id,
            "app-b",
            "App B",
            "web",
            "client-b",
            "secret-b",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create service b");
        let now = chrono::Utc::now().naive_utc();
        PlanStore::create(
            DB::Conn(&db),
            "plan-a",
            &service_a.id,
            "Plan A",
            None,
            0,
            "USD",
            "[]",
            None,
            true,
            now,
        )
        .await
        .expect("create plan a");
        PlanStore::create(
            DB::Conn(&db),
            "plan-b",
            &service_b.id,
            "Plan B",
            None,
            0,
            "USD",
            "[]",
            None,
            true,
            now,
        )
        .await
        .expect("create plan b");

        let identity_only = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "identity-only@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create identity-only user")
        .0;
        let subscription_only = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "subscription-only@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create subscription-only user")
        .0;
        let both = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "both@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create both user")
        .0;
        let outsider = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "outsider@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create outsider")
        .0;

        IdentityStore::create(
            DB::Conn(&db),
            &identity_only.id,
            "github",
            "identity-only",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service_a.id),
        )
        .await
        .expect("create identity-only identity");
        IdentityStore::create(
            DB::Conn(&db),
            &both.id,
            "github",
            "both",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service_a.id),
        )
        .await
        .expect("create both identity");
        IdentityStore::create(
            DB::Conn(&db),
            &both.id,
            "google",
            "both-google",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service_a.id),
        )
        .await
        .expect("create duplicate service identity for same user");

        SubscriptionStore::create(
            DB::Conn(&db),
            &subscription_only.id,
            &service_a.id,
            "plan-a",
            "active",
            now,
        )
        .await
        .expect("create service a subscription");
        SubscriptionStore::create(
            DB::Conn(&db),
            &both.id,
            &service_b.id,
            "plan-b",
            "active",
            now,
        )
        .await
        .expect("create service b subscription");
        let plan_counts = SubscriptionStore::count_active_by_plans(
            DB::Conn(&db),
            &[
                "plan-a".to_string(),
                "plan-b".to_string(),
                "missing".to_string(),
            ],
        )
        .await
        .expect("count active subscriptions by plan");
        assert_eq!(plan_counts.get("plan-a"), Some(&1));
        assert_eq!(plan_counts.get("plan-b"), Some(&1));
        assert_eq!(plan_counts.get("missing"), None);

        assert_eq!(
            IdentityStore::count_users_by_service(DB::Conn(&db), &service_a.id)
                .await
                .expect("count distinct service users"),
            2
        );
        let service_a_identity_users =
            IdentityStore::list_user_details_by_service(DB::Conn(&db), &service_a.id, 10, 0)
                .await
                .expect("list distinct service user details");
        let service_a_identity_user_ids: HashSet<_> = service_a_identity_users
            .iter()
            .map(|user| user.id.as_str())
            .collect();
        assert_eq!(service_a_identity_user_ids.len(), 2);
        assert!(service_a_identity_user_ids.contains(identity_only.id.as_str()));
        assert!(service_a_identity_user_ids.contains(both.id.as_str()));

        let all = SubscriptionStore::list_end_users_by_org(DB::Conn(&db), &org.id, None, 10, 0)
            .await
            .expect("list all end users");
        let all_ids: HashSet<_> = all.iter().map(|user| user.id.as_str()).collect();
        assert_eq!(all_ids.len(), 3);
        assert!(all_ids.contains(identity_only.id.as_str()));
        assert!(all_ids.contains(subscription_only.id.as_str()));
        assert!(all_ids.contains(both.id.as_str()));
        assert!(!all_ids.contains(outsider.id.as_str()));
        assert_eq!(
            SubscriptionStore::count_end_users_by_org(DB::Conn(&db), &org.id, None)
                .await
                .expect("count all end users"),
            3
        );

        let service_a_users = SubscriptionStore::list_end_users_by_org(
            DB::Conn(&db),
            &org.id,
            Some(&service_a.id),
            10,
            0,
        )
        .await
        .expect("list service a end users");
        let service_a_ids: HashSet<_> = service_a_users
            .iter()
            .map(|user| user.id.as_str())
            .collect();
        assert_eq!(service_a_ids.len(), 3);
        assert!(service_a_ids.contains(identity_only.id.as_str()));
        assert!(service_a_ids.contains(subscription_only.id.as_str()));
        assert!(service_a_ids.contains(both.id.as_str()));

        let service_b_users = SubscriptionStore::list_end_users_by_org(
            DB::Conn(&db),
            &org.id,
            Some(&service_b.id),
            10,
            0,
        )
        .await
        .expect("list service b end users");
        assert_eq!(service_b_users.len(), 1);
        assert_eq!(service_b_users[0].id, both.id);
        assert_eq!(
            SubscriptionStore::count_end_users_by_org(DB::Conn(&db), &org.id, Some(&service_b.id))
                .await
                .expect("count service b end users"),
            1
        );
    }
}
