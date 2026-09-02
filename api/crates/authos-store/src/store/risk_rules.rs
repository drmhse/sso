use crate::db::DB;
use crate::entities::{prelude::RiskRules, risk_rules};
use crate::error::Result;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct RiskRulesStore;

impl RiskRulesStore {
    /// Create default risk rules for an organization
    pub async fn create_default(db: DB<'_>, org_id: &str) -> Result<risk_rules::Model> {
        let now = Utc::now().naive_utc();
        let rules = risk_rules::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            enforcement_mode: Set("log_only".to_string()), // Start in shadow mode
            low_threshold: Set(30),
            medium_threshold: Set(70),
            new_device_score: Set(20),
            impossible_travel_score: Set(50),
            velocity_threshold: Set(10),
            velocity_score: Set(30),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let result = rules.insert(&db).await?;
        Ok(result)
    }

    /// Find risk rules by organization ID
    pub async fn find_by_org(db: DB<'_>, org_id: &str) -> Result<Option<risk_rules::Model>> {
        let rules = RiskRules::find()
            .filter(risk_rules::Column::OrgId.eq(org_id))
            .one(&db)
            .await?;

        Ok(rules)
    }

    /// Find risk rules by ID
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<risk_rules::Model>> {
        let rules = RiskRules::find()
            .filter(risk_rules::Column::Id.eq(id))
            .one(&db)
            .await?;

        Ok(rules)
    }

    /// Update risk rules
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        db: DB<'_>,
        org_id: &str,
        enforcement_mode: Option<String>,
        low_threshold: Option<i32>,
        medium_threshold: Option<i32>,
        new_device_score: Option<i32>,
        impossible_travel_score: Option<i32>,
        velocity_threshold: Option<i32>,
        velocity_score: Option<i32>,
    ) -> Result<risk_rules::Model> {
        let existing = Self::find_by_org(db.clone(), org_id).await?;

        let rules = if let Some(existing) = existing {
            let mut active: risk_rules::ActiveModel = existing.into();

            if let Some(mode) = enforcement_mode {
                active.enforcement_mode = Set(mode);
            }
            if let Some(threshold) = low_threshold {
                active.low_threshold = Set(threshold);
            }
            if let Some(threshold) = medium_threshold {
                active.medium_threshold = Set(threshold);
            }
            if let Some(score) = new_device_score {
                active.new_device_score = Set(score);
            }
            if let Some(score) = impossible_travel_score {
                active.impossible_travel_score = Set(score);
            }
            if let Some(threshold) = velocity_threshold {
                active.velocity_threshold = Set(threshold);
            }
            if let Some(score) = velocity_score {
                active.velocity_score = Set(score);
            }

            active.updated_at = Set(Utc::now().naive_utc());
            active.update(&db).await?
        } else {
            // Create default if doesn't exist
            Self::create_default(db, org_id).await?
        };

        Ok(rules)
    }

    /// Delete risk rules for an organization
    pub async fn delete(db: DB<'_>, org_id: &str) -> Result<bool> {
        let rules = RiskRules::find()
            .filter(risk_rules::Column::OrgId.eq(org_id))
            .one(&db)
            .await?;

        if let Some(rules) = rules {
            let active: risk_rules::ActiveModel = rules.into();
            active.delete(&db).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{organizations::OrganizationStore, users::UserStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn risk_rule_update_and_delete_preserve_other_organization() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "risk-owner@example.test", None, false)
            .await
            .expect("create owner");
        let org_a =
            OrganizationStore::create(DB::Conn(&db), "risk-org-a", "Risk Org A", &owner.id, None)
                .await
                .expect("create org A");
        let org_b =
            OrganizationStore::create(DB::Conn(&db), "risk-org-b", "Risk Org B", &owner.id, None)
                .await
                .expect("create org B");
        RiskRulesStore::create_default(DB::Conn(&db), &org_a.id)
            .await
            .expect("create org A rules");
        let rules_b = RiskRulesStore::create_default(DB::Conn(&db), &org_b.id)
            .await
            .expect("create org B rules");

        RiskRulesStore::update(
            DB::Conn(&db),
            &org_a.id,
            Some("block".to_string()),
            Some(10),
            Some(20),
            Some(90),
            Some(90),
            Some(2),
            Some(90),
        )
        .await
        .expect("update org A rules");
        let preserved_b = RiskRulesStore::find_by_org(DB::Conn(&db), &org_b.id)
            .await
            .expect("load org B rules")
            .expect("org B rules remain");
        assert_eq!(preserved_b.id, rules_b.id);
        assert_eq!(preserved_b.enforcement_mode, "log_only");
        assert_eq!(preserved_b.low_threshold, 30);
        assert_eq!(preserved_b.medium_threshold, 70);

        assert!(RiskRulesStore::delete(DB::Conn(&db), &org_a.id)
            .await
            .expect("delete org A rules"));
        assert!(RiskRulesStore::find_by_org(DB::Conn(&db), &org_b.id)
            .await
            .expect("load preserved org B rules")
            .is_some());
    }
}
