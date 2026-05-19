//! `SeaORM` Entity for per-service user consent to connected account tokens.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "service_provider_grants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub service_id: String,
    #[sea_orm(column_type = "Text")]
    pub connected_account_id: String,
    #[sea_orm(column_type = "Text")]
    pub provider: String,
    #[sea_orm(column_type = "Text")]
    pub scopes: String,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    pub granted_at: DateTime,
    pub last_used_at: Option<DateTime>,
    pub revoked_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::connected_accounts::Entity",
        from = "Column::ConnectedAccountId",
        to = "super::connected_accounts::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    ConnectedAccounts,
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

impl Related<super::connected_accounts::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ConnectedAccounts.def()
    }
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
