//! `SeaORM` Entity for upstream_providers table

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "upstream_providers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub org_id: String,
    #[sea_orm(column_type = "Text")]
    pub connection_id: String,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub provider_type: String,
    #[sea_orm(column_type = "Text")]
    pub client_id: String,
    #[sea_orm(column_type = "Blob")]
    #[serde(skip_serializing)]
    pub client_secret_encrypted: Vec<u8>,
    #[sea_orm(column_type = "Text")]
    #[serde(skip_serializing)]
    pub encryption_key_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub authorization_url: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub token_url: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub userinfo_url: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub discovery_url: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub scopes: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub issuer: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub metadata: Option<String>,
    pub enabled: bool,
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
