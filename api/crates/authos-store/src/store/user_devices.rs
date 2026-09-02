use crate::db::DB;
use crate::entities::{prelude::UserDevices, user_devices};
use crate::error::Result;
use chrono::{NaiveDateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;

pub struct UserDevicesStore;

impl UserDevicesStore {
    /// Create a new device trust record
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        trust_token_hash: &str,
        name: &str,
        last_ip: Option<String>,
        expires_at: NaiveDateTime,
    ) -> Result<user_devices::Model> {
        let device = user_devices::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            trust_token_hash: Set(trust_token_hash.to_string()),
            name: Set(name.to_string()),
            last_ip: Set(last_ip),
            last_seen_at: Set(Utc::now().naive_utc()),
            expires_at: Set(expires_at),
            is_trusted: Set(true),
            created_at: Set(Utc::now().naive_utc()),
        };

        let result = device.insert(&db).await?;
        Ok(result)
    }

    /// Find a device by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<user_devices::Model>> {
        let device = UserDevices::find()
            .filter(user_devices::Column::TrustTokenHash.eq(token_hash))
            .one(&db)
            .await?;

        Ok(device)
    }

    /// Find a device by ID
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<user_devices::Model>> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(id))
            .one(&db)
            .await?;

        Ok(device)
    }

    /// List all devices for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<user_devices::Model>> {
        let devices = UserDevices::find()
            .filter(user_devices::Column::UserId.eq(user_id))
            .order_by_desc(user_devices::Column::LastSeenAt)
            .all(&db)
            .await?;

        Ok(devices)
    }

    /// Update last seen information
    ///
    /// OPTIMIZATION: Only writes to DB if >5 minutes since last update.
    /// This dramatically reduces write pressure for frequently-used devices.
    pub async fn update_last_seen(db: DB<'_>, device_id: &str, ip: Option<String>) -> Result<()> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .one(&db)
            .await?;

        if let Some(device) = device {
            // OPTIMIZATION: Only update if >5 minutes since last update
            let now = Utc::now().naive_utc();
            let minutes_since_update = (now - device.last_seen_at).num_minutes();
            if minutes_since_update <= 5 {
                // Skip redundant write - device was recently seen
                return Ok(());
            }

            let mut active: user_devices::ActiveModel = device.into();
            active.last_seen_at = Set(now);
            if let Some(ip) = ip {
                active.last_ip = Set(Some(ip));
            }
            active.update(&db).await?;
        }

        Ok(())
    }

    /// Revoke a device (set is_trusted to false)
    pub async fn revoke(db: DB<'_>, device_id: &str, user_id: &str) -> Result<bool> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .filter(user_devices::Column::UserId.eq(user_id))
            .one(&db)
            .await?;

        if let Some(device) = device {
            let mut active: user_devices::ActiveModel = device.into();
            active.is_trusted = Set(false);
            active.update(&db).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete a device
    pub async fn delete(db: DB<'_>, device_id: &str, user_id: &str) -> Result<bool> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .filter(user_devices::Column::UserId.eq(user_id))
            .one(&db)
            .await?;

        if let Some(device) = device {
            let active: user_devices::ActiveModel = device.into();
            active.delete(&db).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clean up expired devices (for background job)
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = Utc::now().naive_utc();
        let result = UserDevices::delete_many()
            .filter(user_devices::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Find a device by ID and user ID (ensures ownership)
    pub async fn find_by_id_and_user(
        db: DB<'_>,
        device_id: &str,
        user_id: &str,
    ) -> Result<Option<user_devices::Model>> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .filter(user_devices::Column::UserId.eq(user_id))
            .one(&db)
            .await?;

        Ok(device)
    }

    /// Find all devices for a user
    pub async fn find_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<user_devices::Model>> {
        let devices = UserDevices::find()
            .filter(user_devices::Column::UserId.eq(user_id))
            .order_by_desc(user_devices::Column::LastSeenAt)
            .all(&db)
            .await?;

        Ok(devices)
    }

    /// Delete all devices for a user except the provided device IDs.
    pub async fn delete_by_user_except_ids(
        db: DB<'_>,
        user_id: &str,
        keep_device_ids: &[String],
    ) -> Result<u64> {
        let mut delete =
            UserDevices::delete_many().filter(user_devices::Column::UserId.eq(user_id));
        if !keep_device_ids.is_empty() {
            delete =
                delete.filter(user_devices::Column::Id.is_not_in(keep_device_ids.iter().cloned()));
        }
        let result = delete.exec(&db).await?;
        Ok(result.rows_affected)
    }

    /// Update device name
    pub async fn update_name(
        db: DB<'_>,
        device_id: &str,
        user_id: &str,
        name: &str,
    ) -> Result<bool> {
        let result = UserDevices::update_many()
            .filter(user_devices::Column::Id.eq(device_id))
            .filter(user_devices::Column::UserId.eq(user_id))
            .col_expr(
                user_devices::Column::Name,
                sea_orm::sea_query::Expr::value(name),
            )
            .exec(&db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Update device expiration time
    pub async fn update_expires_at(
        db: DB<'_>,
        device_id: &str,
        user_id: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<bool> {
        let result = UserDevices::update_many()
            .filter(user_devices::Column::Id.eq(device_id))
            .filter(user_devices::Column::UserId.eq(user_id))
            .col_expr(
                user_devices::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(*expires_at),
            )
            .exec(&db)
            .await?;
        Ok(result.rows_affected == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::users::UserStore;
    use chrono::Duration;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn user_scoped_device_mutations_deny_other_user_and_preserve_state() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "device-owner@example.test", None, false)
            .await
            .expect("create owner");
        let other = UserStore::create(DB::Conn(&db), "device-other@example.test", None, false)
            .await
            .expect("create other user");
        let original_expiry = (Utc::now() + Duration::days(10)).naive_utc();
        let device = UserDevicesStore::create(
            DB::Conn(&db),
            &owner.id,
            "owner-token-hash",
            "Owner device",
            None,
            original_expiry,
        )
        .await
        .expect("create device");

        assert!(!UserDevicesStore::update_name(
            DB::Conn(&db),
            &device.id,
            &other.id,
            "Stolen device"
        )
        .await
        .expect("deny cross-user rename"));
        let attacker_expiry = (Utc::now() + Duration::days(3650)).naive_utc();
        assert!(!UserDevicesStore::update_expires_at(
            DB::Conn(&db),
            &device.id,
            &other.id,
            &attacker_expiry
        )
        .await
        .expect("deny cross-user trust extension"));
        assert!(
            !UserDevicesStore::delete(DB::Conn(&db), &device.id, &other.id)
                .await
                .expect("deny cross-user delete")
        );

        let unchanged = UserDevicesStore::find_by_id(DB::Conn(&db), &device.id)
            .await
            .expect("load device")
            .expect("device preserved");
        assert_eq!(unchanged.name, "Owner device");
        assert_eq!(unchanged.expires_at, original_expiry);
        assert!(unchanged.is_trusted);

        assert!(UserDevicesStore::update_name(
            DB::Conn(&db),
            &device.id,
            &owner.id,
            "Renamed by owner"
        )
        .await
        .expect("owner rename"));
        assert!(
            UserDevicesStore::revoke(DB::Conn(&db), &device.id, &owner.id)
                .await
                .expect("owner revoke")
        );
    }
}
