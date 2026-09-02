//! `SeaORM` Entity for system_jobs table

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "system_jobs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub job_type: String,
    #[sea_orm(column_type = "Text")]
    pub payload: String,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    pub priority: i32,
    pub max_retries: i32,
    pub attempt_count: i32,
    pub scheduled_for: DateTime,
    pub last_attempt_at: Option<DateTime>,
    pub completed_at: Option<DateTime>,
    pub failed_at: Option<DateTime>,
    #[sea_orm(column_type = "Text", nullable)]
    pub error_message: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub worker_id: Option<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
