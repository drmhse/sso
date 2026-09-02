// `SeaORM` Entity for siem_configs table

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "siem_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub org_id: String,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub provider: String,
    #[sea_orm(column_type = "Text")]
    pub endpoint_url: String,
    #[sea_orm(column_type = "Text", nullable)]
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    #[serde(skip_serializing)]
    pub auth_header: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub batch_size: String,
    pub enabled: bool,
    pub last_successful_batch_at: Option<DateTime>,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_processed_log_id: Option<String>,
    #[sea_orm(column_type = "Integer")]
    pub failure_count: i32,
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
}

impl Related<super::organizations::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organizations.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
