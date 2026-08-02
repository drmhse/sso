//! SeaORM entity for short-lived OAuth authorization grants.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_authorization_grants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text", unique)]
    #[serde(skip_serializing)]
    pub token_hash: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub service_id: String,
    #[sea_orm(column_type = "Text")]
    pub client_id: String,
    #[sea_orm(column_type = "Text")]
    pub resource: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub scope: Option<String>,
    pub expires_at: DateTime,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::services::Entity",
        from = "Column::ServiceId",
        to = "super::services::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Services,
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Users,
}

impl Related<super::services::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Services.def()
    }
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
