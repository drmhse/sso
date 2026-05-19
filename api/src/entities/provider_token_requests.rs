//! `SeaORM` Entity for one-time hosted provider token request states.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "provider_token_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub state: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub service_id: String,
    #[sea_orm(column_type = "Text")]
    pub provider: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub connected_account_id: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub requested_scopes: String,
    #[sea_orm(column_type = "Text")]
    pub redirect_uri: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub client_state: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    pub created_at: DateTime,
    pub expires_at: DateTime,
    pub completed_at: Option<DateTime>,
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
