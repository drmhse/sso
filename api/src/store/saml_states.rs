use crate::entities::prelude::SamlStates;
use crate::entities::saml_states;
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct SamlStateStore;

impl SamlStateStore {
    /// Create a new SAML state
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        state_id: &str,
        service_id: &str,
        saml_request: &str,
        relay_state: Option<&str>,
        acs_url: &str,
        request_id: Option<&str>,
        issuer: Option<&str>,
        binding: Option<&str>,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<saml_states::Model> {
        let now = Utc::now().naive_utc();
        let new_state = saml_states::ActiveModel {
            state_id: Set(state_id.to_string()),
            service_id: Set(service_id.to_string()),
            saml_request: Set(saml_request.to_string()),
            relay_state: Set(relay_state.map(|s| s.to_string())),
            acs_url: Set(acs_url.to_string()),
            request_id: Set(request_id.map(|s| s.to_string())),
            issuer: Set(issuer.map(|s| s.to_string())),
            binding: Set(binding.map(|s| s.to_string())),
            user_id: Set(None),
            created_at: Set(now),
            expires_at: Set(*expires_at),
        };

        let state = new_state.insert(&db).await?;
        Ok(state)
    }

    /// Find a SAML state by state_id (only if not expired)
    pub async fn find_by_state_id(
        db: DB<'_>,
        state_id: &str,
    ) -> Result<Option<saml_states::Model>> {
        let now = Utc::now().naive_utc();

        let state = SamlStates::find()
            .filter(saml_states::Column::StateId.eq(state_id))
            .filter(saml_states::Column::ExpiresAt.gt(now))
            .one(&db)
            .await?;

        Ok(state)
    }

    /// Validate that a SAML state exists and is not expired
    pub async fn validate_state(db: DB<'_>, state_id: &str) -> Result<bool> {
        let state = Self::find_by_state_id(db, state_id).await?;
        Ok(state.is_some())
    }

    /// Update user_id for a SAML state
    pub async fn update_user_id(db: DB<'_>, state_id: &str, user_id: &str) -> Result<()> {
        use sea_orm::sea_query::Expr;

        SamlStates::update_many()
            .col_expr(saml_states::Column::UserId, Expr::value(user_id))
            .filter(saml_states::Column::StateId.eq(state_id))
            .exec(&db)
            .await?;

        Ok(())
    }

    /// Delete a SAML state by state_id
    pub async fn delete(db: DB<'_>, state_id: &str) -> Result<u64> {
        let result = SamlStates::delete_many()
            .filter(saml_states::Column::StateId.eq(state_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete expired SAML states
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = Utc::now().naive_utc();

        let result = SamlStates::delete_many()
            .filter(saml_states::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}
