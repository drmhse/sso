use crate::entities::{prelude::UserDevices, user_devices};
use crate::error::Result;
use crate::store::DB;
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

    /// Delete a device by ID only
    pub async fn delete_by_id(db: DB<'_>, device_id: &str) -> Result<()> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .one(&db)
            .await?;

        if let Some(device) = device {
            let active: user_devices::ActiveModel = device.into();
            active.delete(&db).await?;
        }

        Ok(())
    }

    /// Update device name
    pub async fn update_name(db: DB<'_>, device_id: &str, name: &str) -> Result<()> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .one(&db)
            .await?;

        if let Some(device) = device {
            let mut active: user_devices::ActiveModel = device.into();
            active.name = Set(name.to_string());
            active.update(&db).await?;
        }

        Ok(())
    }

    /// Update device expiration time
    pub async fn update_expires_at(
        db: DB<'_>,
        device_id: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<()> {
        let device = UserDevices::find()
            .filter(user_devices::Column::Id.eq(device_id))
            .one(&db)
            .await?;

        if let Some(device) = device {
            let mut active: user_devices::ActiveModel = device.into();
            active.expires_at = Set(*expires_at);
            active.update(&db).await?;
        }

        Ok(())
    }
}
