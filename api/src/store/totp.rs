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
