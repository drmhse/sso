use crate::entities::organization_tiers;
use crate::entities::prelude::OrganizationTiers;
use crate::error::Result;
use crate::store::DB;
use sea_orm::{ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait};

pub struct OrganizationTierStore;

impl OrganizationTierStore {
    /// Find a tier by its ID
    pub async fn find_by_id(
        db: DB<'_>,
        tier_id: &str,
    ) -> Result<Option<organization_tiers::Model>> {
        let result = OrganizationTiers::find()
            .filter(organization_tiers::Column::Id.eq(tier_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find tiers by IDs.
    pub async fn find_by_ids(
        db: DB<'_>,
        tier_ids: &[String],
    ) -> Result<Vec<organization_tiers::Model>> {
        if tier_ids.is_empty() {
            return Ok(Vec::new());
        }

        let result = OrganizationTiers::find()
            .filter(organization_tiers::Column::Id.is_in(tier_ids.iter().cloned()))
            .all(&db)
            .await?;
        Ok(result)
    }

    /// Find a tier by its name
    pub async fn find_by_name(db: DB<'_>, name: &str) -> Result<Option<organization_tiers::Model>> {
        let result = OrganizationTiers::find()
            .filter(organization_tiers::Column::Name.eq(name))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find tier for an organization (by organization ID)
    pub async fn find_by_org_id(
        db: DB<'_>,
        org_id: &str,
    ) -> Result<Option<organization_tiers::Model>> {
        use crate::entities::organizations;

        let result = OrganizationTiers::find()
            .select_only()
            .column(organization_tiers::Column::Id)
            .column(organization_tiers::Column::Name)
            .column(organization_tiers::Column::DisplayName)
            .column(organization_tiers::Column::DefaultMaxServices)
            .column(organization_tiers::Column::DefaultMaxUsers)
            .column(organization_tiers::Column::PriceCents)
            .column(organization_tiers::Column::Currency)
            .column(organization_tiers::Column::Features)
            .column(organization_tiers::Column::CreatedAt)
            .join(
                JoinType::InnerJoin,
                organization_tiers::Relation::Organizations.def(),
            )
            .filter(organizations::Column::Id.eq(org_id))
            .into_model::<organization_tiers::Model>()
            .one(&db)
            .await?;
        Ok(result)
    }

    /// List all tiers
    pub async fn list_all(db: DB<'_>) -> Result<Vec<organization_tiers::Model>> {
        let tiers = OrganizationTiers::find().all(&db).await?;
        Ok(tiers)
    }
}
