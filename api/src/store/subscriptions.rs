use crate::error::Result;
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, Set};

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
        use sea_orm::{JoinType, Order, QueryOrder, QuerySelect, RelationTrait};
        use std::collections::HashSet;

        // Get user IDs from identities for this org (optionally filtered by service)
        let mut identity_query = identities::Entity::find()
            .filter(identities::Column::IssuingOrgId.eq(org_id))
            .select_only()
            .column(identities::Column::UserId);

        if let Some(svc_id) = service_id {
            identity_query = identity_query.filter(identities::Column::IssuingServiceId.eq(svc_id));
        }

        let identity_user_ids: Vec<String> = identity_query.into_tuple().all(&db).await?;

        // Get user IDs from subscriptions for this org (optionally filtered by service)
        let mut sub_query = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .select_only()
            .column(subscriptions::Column::UserId);

        if let Some(svc_id) = service_id {
            sub_query = sub_query.filter(subscriptions::Column::ServiceId.eq(svc_id));
        } else {
            sub_query = sub_query.filter(services::Column::OrgId.eq(org_id));
        }

        let sub_user_ids: Vec<String> = sub_query.into_tuple().all(&db).await?;

        // Combine and deduplicate user IDs
        let all_user_ids: Vec<String> = identity_user_ids
            .into_iter()
            .chain(sub_user_ids)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if all_user_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Fetch user details with pagination
        let results = users::Entity::find()
            .filter(users::Column::Id.is_in(all_user_ids))
            .order_by(users::Column::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
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
        use crate::entities::{identities, services, subscriptions};
        use sea_orm::{JoinType, QuerySelect, RelationTrait};
        use std::collections::HashSet;

        // Get user IDs from identities for this org (optionally filtered by service)
        let mut identity_query = identities::Entity::find()
            .filter(identities::Column::IssuingOrgId.eq(org_id))
            .select_only()
            .column(identities::Column::UserId);

        if let Some(svc_id) = service_id {
            identity_query = identity_query.filter(identities::Column::IssuingServiceId.eq(svc_id));
        }

        let identity_user_ids: Vec<String> = identity_query.into_tuple().all(&db).await?;

        // Get user IDs from subscriptions for this org (optionally filtered by service)
        let mut sub_query = subscriptions::Entity::find()
            .join(JoinType::InnerJoin, subscriptions::Relation::Services.def())
            .select_only()
            .column(subscriptions::Column::UserId);

        if let Some(svc_id) = service_id {
            sub_query = sub_query.filter(subscriptions::Column::ServiceId.eq(svc_id));
        } else {
            sub_query = sub_query.filter(services::Column::OrgId.eq(org_id));
        }

        let sub_user_ids: Vec<String> = sub_query.into_tuple().all(&db).await?;

        // Combine and deduplicate user IDs, return count
        let unique_user_ids: HashSet<String> =
            identity_user_ids.into_iter().chain(sub_user_ids).collect();

        Ok(unique_user_ids.len() as i64)
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

        let results = query
            .limit(limit as u64)
            .offset(offset as u64)
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
