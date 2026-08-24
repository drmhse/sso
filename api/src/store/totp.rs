use crate::entities::prelude::{TotpBackupCodes, UserTotpSecrets};
use crate::entities::{totp_backup_codes, user_totp_secrets};
use crate::error::Result;
use crate::store::DB;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

pub struct TotpStore;

impl TotpStore {
    /// Check if a user has MFA/TOTP enabled
    pub async fn is_enabled(db: DB<'_>, user_id: &str) -> Result<bool> {
        let totp_secret = UserTotpSecrets::find()
            .filter(user_totp_secrets::Column::UserId.eq(user_id))
            .one(&db)
            .await?;

        Ok(totp_secret.map(|s| s.enabled).unwrap_or(false))
    }

    /// Find TOTP secret by user ID
    pub async fn find_by_user(
        db: DB<'_>,
        user_id: &str,
    ) -> Result<Option<user_totp_secrets::Model>> {
        let result = UserTotpSecrets::find()
            .filter(user_totp_secrets::Column::UserId.eq(user_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Delete TOTP secret for a user
    pub async fn delete_totp_secret(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = UserTotpSecrets::delete_many()
            .filter(user_totp_secrets::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Delete all backup codes for a user
    pub async fn delete_backup_codes(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = TotpBackupCodes::delete_many()
            .filter(totp_backup_codes::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Count backup codes for a user
    pub async fn count_backup_codes(db: DB<'_>, user_id: &str) -> Result<u64> {
        let count = TotpBackupCodes::find()
            .filter(totp_backup_codes::Column::UserId.eq(user_id))
            .count(&db)
            .await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::DatabaseConnection;
    use sea_orm::{ActiveModelTrait, Database, Set};
    use uuid::Uuid;

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    #[tokio::test]
    async fn totp_lifecycle_reads_writes_and_deletes() {
        let db = db().await;
        let user =
            crate::store::users::UserStore::create(DB::Conn(&db), "totp@example.test", None, false)
                .await
                .expect("create user");

        assert!(!TotpStore::is_enabled(DB::Conn(&db), &user.id)
            .await
            .unwrap());

        let secret = user_totp_secrets::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user.id.clone()),
            secret_encrypted: Set(b"enc".to_vec()),
            encryption_key_id: Set("k1".to_string()),
            enabled: Set(false),
            enabled_at: Set(None),
            created_at: Set(Utc::now().naive_utc()),
        };
        secret.insert(&db).await.expect("seed unconfirmed secret");

        // Unconfirmed means not yet enabled.
        assert!(!TotpStore::is_enabled(DB::Conn(&db), &user.id)
            .await
            .unwrap());
        assert!(TotpStore::find_by_user(DB::Conn(&db), &user.id)
            .await
            .unwrap()
            .is_some());

        // Backup codes.
        let code = totp_backup_codes::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user.id.clone()),
            code_hash: Set("hash-1".to_string()),
            used: Set(false),
            used_at: Set(None),
            created_at: Set(Utc::now().naive_utc()),
        };
        code.insert(&db).await.expect("seed backup code");
        assert_eq!(
            TotpStore::count_backup_codes(DB::Conn(&db), &user.id)
                .await
                .unwrap(),
            1
        );

        // Deleting the secret removes codes too (or independently).
        TotpStore::delete_totp_secret(DB::Conn(&db), &user.id)
            .await
            .unwrap();
        TotpStore::delete_backup_codes(DB::Conn(&db), &user.id)
            .await
            .unwrap();
        assert_eq!(
            TotpStore::count_backup_codes(DB::Conn(&db), &user.id)
                .await
                .unwrap(),
            0
        );
    }
}
