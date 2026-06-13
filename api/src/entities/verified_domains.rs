//! `SeaORM` Entity for verified_domains table

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "verified_domains")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub org_id: String,
    #[sea_orm(column_type = "Text")]
    pub domain: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub upstream_provider_id: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub login_policy: String,
    #[sea_orm(column_type = "Text")]
    pub verification_token: String,
    pub verified: bool,
    pub verified_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organizations::Entity",
        from = "Column::OrgId",
        to = "super::organizations::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Organizations,
    #[sea_orm(
        belongs_to = "super::upstream_providers::Entity",
        from = "Column::UpstreamProviderId",
        to = "super::upstream_providers::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    UpstreamProviders,
}

impl Related<super::organizations::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organizations.def()
    }
}

impl Related<super::upstream_providers::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UpstreamProviders.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
