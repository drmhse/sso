use crate::entities::{prelude::UserPasskeys, user_passkeys};
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct UserPasskeysStore;

impl UserPasskeysStore {
    /// Create a new passkey
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        credential_id: &str,
        public_key: &str,
        aaguid: Option<String>,
        name: &str,
        backup_eligible: bool,
        backup_state: bool,
        transports: Option<String>,
    ) -> Result<user_passkeys::Model> {
        let passkey = user_passkeys::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            credential_id: Set(credential_id.to_string()),
            public_key: Set(public_key.to_string()),
            counter: Set(0),
            aaguid: Set(aaguid),
            name: Set(name.to_string()),
            backup_eligible: Set(backup_eligible),
            backup_state: Set(backup_state),
            transports: Set(transports),
            last_used_at: Set(None),
            created_at: Set(Utc::now().naive_utc()),
        };

        let result = passkey.insert(&db).await?;
        Ok(result)
    }

    /// Find a passkey by credential ID
    pub async fn find_by_credential_id(
        db: DB<'_>,
        credential_id: &str,
    ) -> Result<Option<user_passkeys::Model>> {
        let passkey = UserPasskeys::find()
            .filter(user_passkeys::Column::CredentialId.eq(credential_id))
            .one(&db)
            .await?;

        Ok(passkey)
    }

    /// Find a passkey by ID
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<user_passkeys::Model>> {
        let passkey = UserPasskeys::find()
            .filter(user_passkeys::Column::Id.eq(id))
            .one(&db)
            .await?;

        Ok(passkey)
    }

    /// List all passkeys for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<user_passkeys::Model>> {
        let passkeys = UserPasskeys::find()
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        Ok(passkeys)
    }

    /// Update the counter and last_used_at after successful authentication
    pub async fn update_after_use(db: DB<'_>, passkey_id: &str, new_counter: i64) -> Result<()> {
        let passkey = UserPasskeys::find()
            .filter(user_passkeys::Column::Id.eq(passkey_id))
            .one(&db)
            .await?;

        if let Some(passkey) = passkey {
            let mut active: user_passkeys::ActiveModel = passkey.into();
            active.counter = Set(new_counter);
            active.last_used_at = Set(Some(Utc::now().naive_utc()));
            active.update(&db).await?;
        }

        Ok(())
    }

    /// Update passkey name
    pub async fn update_name(db: DB<'_>, passkey_id: &str, new_name: &str) -> Result<()> {
        let passkey = UserPasskeys::find()
            .filter(user_passkeys::Column::Id.eq(passkey_id))
            .one(&db)
            .await?;

        if let Some(passkey) = passkey {
            let mut active: user_passkeys::ActiveModel = passkey.into();
            active.name = Set(new_name.to_string());
            active.update(&db).await?;
        }

        Ok(())
    }

    /// Delete a passkey
    pub async fn delete(db: DB<'_>, passkey_id: &str, user_id: &str) -> Result<bool> {
        let passkey = UserPasskeys::find()
            .filter(user_passkeys::Column::Id.eq(passkey_id))
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .one(&db)
            .await?;

        if let Some(passkey) = passkey {
            let active: user_passkeys::ActiveModel = passkey.into();
            active.delete(&db).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Count passkeys for a user
    pub async fn count_by_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        let count = UserPasskeys::find()
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .count(&db)
            .await?;

        Ok(count)
    }
}
