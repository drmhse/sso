//! Durable outbox for login, organization, MFA, and platform audit events.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_outbox")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(64))"
    )]
    pub id: String,
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub event_id: String,
    #[sea_orm(column_type = "String(StringLen::N(32))")]
    pub event_kind: String,
    #[sea_orm(column_type = "Text")]
    pub payload: String,
    #[sea_orm(column_type = "String(StringLen::N(32))")]
    pub status: String,
    pub attempts: i32,
    pub available_at: DateTime,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_error_code: Option<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub dead_lettered_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
