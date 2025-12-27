//! `SeaORM` Entity for log_streams table

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "log_streams")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub org_id: String,
    #[sea_orm(column_type = "Text")]
    pub name: String, // e.g. "Prod Datadog"
    #[sea_orm(column_type = "Text")]
    pub stream_type: String, // 'http', 's3', 'datadog'
    pub config_encrypted: Vec<u8>, // Encrypted JSON
    #[sea_orm(column_type = "Text")]
    pub status: String, // 'active', 'paused', 'error'
    pub last_delivery_at: Option<DateTime>,
    #[sea_orm(column_type = "Integer", default_value = "0")]
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
