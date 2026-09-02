use crate::db::DB;
use crate::entities::{prelude::UserPasskeys, user_passkeys};
use crate::error::Result;
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

    pub async fn find_by_id_for_user(
        db: DB<'_>,
        id: &str,
        user_id: &str,
    ) -> Result<Option<user_passkeys::Model>> {
        Ok(UserPasskeys::find()
            .filter(user_passkeys::Column::Id.eq(id))
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .one(&db)
            .await?)
    }

    /// List all passkeys for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<user_passkeys::Model>> {
        let passkeys = UserPasskeys::find()
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        Ok(passkeys)
    }

    /// Perform the public passkey-start lookup without assigning a fixed
    /// sentinel user ID. `None` uses an impossible typed predicate because
    /// `user_passkeys.user_id` is non-null on every supported schema.
    pub async fn list_for_public_auth_lookup(
        db: DB<'_>,
        user_id: Option<&str>,
    ) -> Result<Vec<user_passkeys::Model>> {
        let query = UserPasskeys::find();
        let query = if let Some(user_id) = user_id {
            query.filter(user_passkeys::Column::UserId.eq(user_id))
        } else {
            query.filter(user_passkeys::Column::UserId.is_null())
        };
        Ok(query.all(&db).await?)
    }

    /// Optimistically persist the complete WebAuthn credential state.
    /// Comparing the serialized prior state prevents a slower ceremony from
    /// overwriting a newer authenticator counter or backup-state transition.
    #[allow(clippy::too_many_arguments)]
    pub async fn compare_and_update_after_use(
        db: DB<'_>,
        passkey_id: &str,
        expected_public_key: &str,
        updated_public_key: &str,
        new_counter: i64,
        backup_eligible: bool,
        backup_state: bool,
    ) -> Result<bool> {
        let result = UserPasskeys::update_many()
            .filter(user_passkeys::Column::Id.eq(passkey_id))
            .filter(user_passkeys::Column::PublicKey.eq(expected_public_key))
            .filter(user_passkeys::Column::Counter.lte(new_counter))
            .col_expr(
                user_passkeys::Column::PublicKey,
                sea_orm::sea_query::Expr::value(updated_public_key),
            )
            .col_expr(
                user_passkeys::Column::Counter,
                sea_orm::sea_query::Expr::value(new_counter),
            )
            .col_expr(
                user_passkeys::Column::BackupEligible,
                sea_orm::sea_query::Expr::value(backup_eligible),
            )
            .col_expr(
                user_passkeys::Column::BackupState,
                sea_orm::sea_query::Expr::value(backup_state),
            )
            .col_expr(
                user_passkeys::Column::LastUsedAt,
                sea_orm::sea_query::Expr::value(Utc::now().naive_utc()),
            )
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Update passkey name
    pub async fn update_name(
        db: DB<'_>,
        passkey_id: &str,
        user_id: &str,
        new_name: &str,
    ) -> Result<bool> {
        let result = UserPasskeys::update_many()
            .filter(user_passkeys::Column::Id.eq(passkey_id))
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .col_expr(
                user_passkeys::Column::Name,
                sea_orm::sea_query::Expr::value(new_name),
            )
            .exec(&db)
            .await?;
        Ok(result.rows_affected == 1)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::users;
    use crate::store::users::UserStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, Set};

    #[tokio::test]
    async fn absent_public_lookup_cannot_collide_with_an_imported_sentinel_user() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let sentinel_id = "00000000-0000-0000-0000-000000000000";
        users::ActiveModel {
            id: Set(sentinel_id.to_string()),
            email: Set("imported-sentinel@example.test".to_string()),
            org_id: Set(None),
            is_platform_owner: Set(false),
            password_hash: Set(None),
            email_verified_at: Set(None),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(None),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        UserPasskeysStore::create(
            DB::Conn(&db),
            sentinel_id,
            "sentinel-credential",
            "invalid-but-unread-public-key",
            None,
            "Imported sentinel passkey",
            false,
            false,
            None,
        )
        .await
        .unwrap();

        assert!(
            UserPasskeysStore::list_for_public_auth_lookup(DB::Conn(&db), None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            UserPasskeysStore::list_for_public_auth_lookup(DB::Conn(&db), Some(sentinel_id))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_passkey_state_updates_have_one_winner_and_no_stale_overwrite() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "passkey-cas@example.com", None, false)
            .await
            .expect("create user");
        let passkey = UserPasskeysStore::create(
            DB::Conn(&db),
            &user.id,
            "credential-id",
            "initial-credential-state",
            None,
            "Passkey",
            false,
            false,
            None,
        )
        .await
        .expect("create passkey");

        let first = UserPasskeysStore::compare_and_update_after_use(
            DB::Conn(&db),
            &passkey.id,
            "initial-credential-state",
            "credential-state-counter-1",
            1,
            false,
            false,
        );
        let second = UserPasskeysStore::compare_and_update_after_use(
            DB::Conn(&db),
            &passkey.id,
            "initial-credential-state",
            "credential-state-counter-2",
            2,
            true,
            true,
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            usize::from(first.expect("first update")) + usize::from(second.expect("second update")),
            1
        );

        let stored = UserPasskeysStore::find_by_id(DB::Conn(&db), &passkey.id)
            .await
            .expect("load passkey")
            .expect("passkey exists");
        assert!(matches!(stored.counter, 1 | 2));
        assert_eq!(
            stored.public_key,
            format!("credential-state-counter-{}", stored.counter)
        );
        assert!(!UserPasskeysStore::compare_and_update_after_use(
            DB::Conn(&db),
            &passkey.id,
            "initial-credential-state",
            "stale-lower-state",
            0,
            false,
            false,
        )
        .await
        .expect("reject stale update"));
        assert!(!UserPasskeysStore::compare_and_update_after_use(
            DB::Conn(&db),
            &passkey.id,
            &stored.public_key,
            "counter-regression-state",
            stored.counter - 1,
            false,
            false,
        )
        .await
        .expect("reject counter regression"));
    }

    #[tokio::test]
    async fn passkey_management_denies_other_user_and_preserves_target() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "passkey-owner@example.test", None, false)
            .await
            .expect("create owner");
        let other = UserStore::create(DB::Conn(&db), "passkey-other@example.test", None, false)
            .await
            .expect("create other user");
        let passkey = UserPasskeysStore::create(
            DB::Conn(&db),
            &owner.id,
            "owner-credential",
            "public-state",
            None,
            "Owner passkey",
            false,
            false,
            None,
        )
        .await
        .expect("create passkey");

        assert!(
            UserPasskeysStore::find_by_id_for_user(DB::Conn(&db), &passkey.id, &other.id)
                .await
                .expect("cross-user lookup")
                .is_none()
        );
        assert!(!UserPasskeysStore::update_name(
            DB::Conn(&db),
            &passkey.id,
            &other.id,
            "Stolen passkey"
        )
        .await
        .expect("deny cross-user rename"));
        assert!(
            !UserPasskeysStore::delete(DB::Conn(&db), &passkey.id, &other.id)
                .await
                .expect("deny cross-user delete")
        );
        let unchanged = UserPasskeysStore::find_by_id(DB::Conn(&db), &passkey.id)
            .await
            .expect("load passkey")
            .expect("passkey preserved");
        assert_eq!(unchanged.name, "Owner passkey");
        assert_eq!(unchanged.public_key, "public-state");
    }
}
