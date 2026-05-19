//! `SeaORM` Entity for user-owned OAuth connected accounts.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "connected_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub provider: String,
    #[sea_orm(column_type = "Text")]
    pub provider_user_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub email: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub display_name: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub access_token: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub refresh_token: Option<String>,
    #[sea_orm(column_type = "Blob", nullable)]
    pub access_token_encrypted: Option<Vec<u8>>,
    #[sea_orm(column_type = "Blob", nullable)]
    pub refresh_token_encrypted: Option<Vec<u8>>,
    #[sea_orm(column_type = "Text", nullable)]
    pub encryption_key_id: Option<String>,
    pub expires_at: Option<DateTime>,
    #[sea_orm(column_type = "Text", nullable)]
    pub scopes: Option<String>,
    pub last_refreshed_at: Option<DateTime>,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    pub linked_at: DateTime,
    pub updated_at: DateTime,
    pub revoked_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Users,
    #[sea_orm(has_many = "super::service_provider_grants::Entity")]
    ServiceProviderGrants,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl Related<super::service_provider_grants::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ServiceProviderGrants.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
