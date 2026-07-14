use crate::entities::plans;
use crate::entities::prelude::Plans;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
use std::collections::HashMap;

#[derive(Debug, FromQueryResult)]
struct CountByService {
    service_id: String,
    count: i64,
}

pub struct PlanStore;

fn checked_price_cents(value: i64) -> Result<i32> {
    if value < 0 {
        return Err(AppError::BadRequest(
            "Plan price_cents must be non-negative".to_string(),
        ));
    }

    i32::try_from(value).map_err(|_| {
        AppError::BadRequest("Plan price_cents exceeds the supported range".to_string())
    })
}

impl PlanStore {
    /// Find a plan by ID
    pub async fn find_by_id(db: DB<'_>, plan_id: &str) -> Result<Option<plans::Model>> {
        let result = Plans::find()
            .filter(plans::Column::Id.eq(plan_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a plan only through its authorized parent service.
    pub async fn find_by_id_and_service(
        db: DB<'_>,
        plan_id: &str,
        service_id: &str,
    ) -> Result<Option<plans::Model>> {
        Ok(Plans::find()
            .filter(plans::Column::Id.eq(plan_id))
            .filter(plans::Column::ServiceId.eq(service_id))
            .one(&db)
            .await?)
    }

    /// Find plans by service ID
    pub async fn find_by_service(db: DB<'_>, service_id: &str) -> Result<Vec<plans::Model>> {
        let plans_list = Plans::find()
            .filter(plans::Column::ServiceId.eq(service_id))
            .all(&db)
            .await?;
        Ok(plans_list)
    }

    /// Count plans by service ID
    pub async fn count_by_service(db: DB<'_>, service_id: &str) -> Result<i64> {
        let count = Plans::find()
            .filter(plans::Column::ServiceId.eq(service_id))
            .count(&db)
            .await? as i64;
        Ok(count)
    }

    /// Count plans grouped by service ID.
    pub async fn count_by_services(
        db: DB<'_>,
        service_ids: &[String],
    ) -> Result<HashMap<String, i64>> {
        if service_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = Plans::find()
            .filter(plans::Column::ServiceId.is_in(service_ids.iter().cloned()))
            .select_only()
            .column(plans::Column::ServiceId)
            .column_as(plans::Column::Id.count(), "count")
            .group_by(plans::Column::ServiceId)
            .into_model::<CountByService>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.service_id, row.count))
            .collect())
    }

    /// Create a new plan
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        plan_id: &str,
        service_id: &str,
        name: &str,
        description: Option<&str>,
        price_cents: i64,
        currency: &str,
        features: &str,
        stripe_price_id: Option<&str>,
        is_default: bool,
        created_at: chrono::NaiveDateTime,
    ) -> Result<()> {
        let price_cents = checked_price_cents(price_cents)?;
        let new_plan = plans::ActiveModel {
            id: Set(plan_id.to_string()),
            service_id: Set(service_id.to_string()),
            name: Set(name.to_string()),
            description: Set(description.map(|s| s.to_string())),
            price_cents: Set(price_cents),
            currency: Set(currency.to_string()),
            features: Set(Some(features.to_string())),
            stripe_price_id: Set(stripe_price_id.map(|s| s.to_string())),
            is_default: Set(is_default),
            created_at: Set(created_at),
        };

        new_plan
            .insert(&db)
            .await
            .map_err(crate::error::handle_sea_orm_error)?;
        Ok(())
    }

    /// Update a plan
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        db: DB<'_>,
        service_id: &str,
        plan_id: &str,
        name: Option<&str>,
        description: Option<Option<&str>>,
        price_cents: Option<i64>,
        currency: Option<&str>,
        features: Option<&str>,
        stripe_price_id: Option<Option<&str>>,
        is_default: Option<bool>,
    ) -> Result<plans::Model> {
        // First, find the plan
        let plan = Plans::find()
            .filter(plans::Column::Id.eq(plan_id))
            .filter(plans::Column::ServiceId.eq(service_id))
            .one(&db)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Plan not found".to_string()))?;

        // Create active model for update
        let mut active_plan: plans::ActiveModel = plan.into();

        // Update fields if provided
        if let Some(n) = name {
            active_plan.name = Set(n.to_string());
        }
        if let Some(d) = description {
            active_plan.description = Set(d.map(|s| s.to_string()));
        }
        if let Some(p) = price_cents {
            active_plan.price_cents = Set(checked_price_cents(p)?);
        }
        if let Some(c) = currency {
            active_plan.currency = Set(c.to_string());
        }
        if let Some(f) = features {
            active_plan.features = Set(Some(f.to_string()));
        }
        if let Some(sp) = stripe_price_id {
            active_plan.stripe_price_id = Set(sp.map(|s| s.to_string()));
        }
        if let Some(d) = is_default {
            active_plan.is_default = Set(d);
        }

        // Save and return updated plan
        let updated_plan = active_plan.update(&db).await?;
        Ok(updated_plan)
    }

    /// Delete a plan
    pub async fn delete(db: DB<'_>, service_id: &str, plan_id: &str) -> Result<()> {
        let result = Plans::delete_many()
            .filter(plans::Column::Id.eq(plan_id))
            .filter(plans::Column::ServiceId.eq(service_id))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(crate::error::AppError::NotFound(
                "Plan not found".to_string(),
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
        services::ServiceStore,
        users::{UserCreationOptions, UserStore},
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use uuid::Uuid;

    #[tokio::test]
    async fn plan_mutations_require_parent_service_and_preserve_other_tenant() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "plan-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org_a =
            OrganizationStore::create(DB::Conn(&db), "plan-org-a", "Plan Org A", &owner.id, None)
                .await
                .expect("create org A");
        let org_b =
            OrganizationStore::create(DB::Conn(&db), "plan-org-b", "Plan Org B", &owner.id, None)
                .await
                .expect("create org B");
        let service_a = ServiceStore::create(
            DB::Conn(&db),
            &org_a.id,
            "service-a",
            "Service A",
            "web",
            &Uuid::new_v4().to_string(),
        )
        .await
        .expect("create service A");
        let service_b = ServiceStore::create(
            DB::Conn(&db),
            &org_b.id,
            "service-b",
            "Service B",
            "web",
            &Uuid::new_v4().to_string(),
        )
        .await
        .expect("create service B");
        let plan_id = Uuid::new_v4().to_string();
        PlanStore::create(
            DB::Conn(&db),
            &plan_id,
            &service_b.id,
            "Protected",
            Some("unchanged"),
            500,
            "USD",
            "[]",
            None,
            false,
            chrono::Utc::now().naive_utc(),
        )
        .await
        .expect("create protected plan");

        assert!(matches!(
            PlanStore::update(
                DB::Conn(&db),
                &service_a.id,
                &plan_id,
                Some("Compromised"),
                None,
                Some(1),
                None,
                None,
                None,
                None,
            )
            .await,
            Err(crate::error::AppError::NotFound(_))
        ));
        assert!(matches!(
            PlanStore::delete(DB::Conn(&db), &service_a.id, &plan_id).await,
            Err(crate::error::AppError::NotFound(_))
        ));

        let preserved = PlanStore::find_by_id(DB::Conn(&db), &plan_id)
            .await
            .expect("load protected plan")
            .expect("protected plan remains");
        assert_eq!(preserved.service_id, service_b.id);
        assert_eq!(preserved.name, "Protected");
        assert_eq!(preserved.description.as_deref(), Some("unchanged"));
        assert_eq!(preserved.price_cents, 500);

        PlanStore::update(
            DB::Conn(&db),
            &service_b.id,
            &plan_id,
            Some("Updated"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("same-service update");

        for supported_price in [0, 1, i64::from(i32::MAX)] {
            PlanStore::update(
                DB::Conn(&db),
                &service_b.id,
                &plan_id,
                None,
                None,
                Some(supported_price),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("supported price update");
            let stored = PlanStore::find_by_id_and_service(DB::Conn(&db), &plan_id, &service_b.id)
                .await
                .expect("load supported price")
                .expect("plan remains");
            assert_eq!(stored.price_cents, supported_price as i32);
        }

        for rejected_price in [-1, i64::MIN, i64::from(i32::MAX) + 1, i64::MAX] {
            assert!(matches!(
                PlanStore::update(
                    DB::Conn(&db),
                    &service_b.id,
                    &plan_id,
                    None,
                    None,
                    Some(rejected_price),
                    None,
                    None,
                    None,
                    None,
                )
                .await,
                Err(AppError::BadRequest(_))
            ));
            let unchanged =
                PlanStore::find_by_id_and_service(DB::Conn(&db), &plan_id, &service_b.id)
                    .await
                    .expect("load unchanged plan")
                    .expect("plan remains after rejected price");
            assert_eq!(unchanged.price_cents, i32::MAX);
        }

        let rejected_plan_id = Uuid::new_v4().to_string();
        assert!(matches!(
            PlanStore::create(
                DB::Conn(&db),
                &rejected_plan_id,
                &service_b.id,
                "Rejected",
                None,
                i64::MAX,
                "USD",
                "[]",
                None,
                false,
                chrono::Utc::now().naive_utc(),
            )
            .await,
            Err(AppError::BadRequest(_))
        ));
        assert!(PlanStore::find_by_id(DB::Conn(&db), &rejected_plan_id)
            .await
            .expect("query rejected plan")
            .is_none());

        PlanStore::delete(DB::Conn(&db), &service_b.id, &plan_id)
            .await
            .expect("same-service delete");
    }

    #[test]
    fn plan_prices_reject_negative_and_out_of_range_values() {
        assert!(matches!(
            checked_price_cents(i64::MIN),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            checked_price_cents(i64::from(i32::MAX) + 1),
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(checked_price_cents(0).expect("zero-priced plan"), 0);
        assert_eq!(checked_price_cents(1).expect("minimum paid plan"), 1);
        assert_eq!(
            checked_price_cents(i64::from(i32::MAX)).expect("maximum supported price"),
            i32::MAX
        );
    }
}
