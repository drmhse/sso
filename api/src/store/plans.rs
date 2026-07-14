use crate::entities::plans;
use crate::entities::prelude::Plans;
use crate::error::Result;
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};

pub struct PlanStore;

impl PlanStore {
    /// Find a plan by ID
    pub async fn find_by_id(db: DB<'_>, plan_id: &str) -> Result<Option<plans::Model>> {
        let result = Plans::find()
            .filter(plans::Column::Id.eq(plan_id))
            .one(&db)
            .await?;
        Ok(result)
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
        let new_plan = plans::ActiveModel {
            id: Set(plan_id.to_string()),
            service_id: Set(service_id.to_string()),
            name: Set(name.to_string()),
            description: Set(description.map(|s| s.to_string())),
            price_cents: Set(price_cents as i32),
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
            active_plan.price_cents = Set(p as i32);
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
    pub async fn delete(db: DB<'_>, plan_id: &str) -> Result<()> {
        let result = Plans::delete_many()
            .filter(plans::Column::Id.eq(plan_id))
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
