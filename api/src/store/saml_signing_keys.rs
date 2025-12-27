use crate::entities::prelude::SamlSigningKeys;
use crate::entities::saml_signing_keys;
use crate::error::Result;
use crate::store::DB;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;

pub struct SamlSigningKeysStore;

impl SamlSigningKeysStore {
    /// Count active signing keys for a service
    pub async fn count_active_by_service(db: DB<'_>, service_id: &str) -> Result<i64> {
        use sea_orm::PaginatorTrait;

        let count = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(true))
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// Find the active signing key for a service
    pub async fn find_active_by_service(
        db: DB<'_>,
        service_id: &str,
    ) -> Result<Option<saml_signing_keys::Model>> {
        let key = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(true))
            .order_by_desc(saml_signing_keys::Column::CreatedAt)
            .one(&db)
            .await?;

        Ok(key)
    }

    /// Deactivate all active keys for a service
    pub async fn deactivate_all_for_service(db: DB<'_>, service_id: &str) -> Result<u64> {
        use sea_orm::sea_query::Expr;

        let result = SamlSigningKeys::update_many()
            .col_expr(saml_signing_keys::Column::IsActive, Expr::value(false))
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(true))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Create a new signing key
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        service_id: &str,
        private_key_encrypted: Vec<u8>,
        public_key: &str,
        encryption_key_id: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        is_active: bool,
    ) -> Result<saml_signing_keys::Model> {
        let now = Utc::now().naive_utc();
        let new_key = saml_signing_keys::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            service_id: Set(service_id.to_string()),
            private_key_encrypted: Set(private_key_encrypted),
            public_key: Set(public_key.to_string()),
            encryption_key_id: Set(encryption_key_id.to_string()),
            valid_from: Set(valid_from.naive_utc()),
            valid_until: Set(valid_until.naive_utc()),
            is_active: Set(is_active),
            created_at: Set(now),
        };

        let key = new_key.insert(&db).await?;
        Ok(key)
    }
}
