use crate::entities::prelude::SamlSigningKeys;
use crate::entities::saml_signing_keys;
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::{DateTime, Utc};
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter,
    QueryOrder, Set,
};

pub const MAX_PUBLISHED_PREVIOUS_CERTIFICATES: usize = 2;
pub const SAML_CERTIFICATE_OVERLAP_DAYS: i64 = 7;

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
            .order_by_desc(saml_signing_keys::Column::Id)
            .one(&db)
            .await?;

        Ok(key)
    }

    /// Find the only key eligible to sign new assertions at `now`.
    pub async fn find_signing_key_by_service_at(
        db: DB<'_>,
        service_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<saml_signing_keys::Model>> {
        let key = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(true))
            .filter(saml_signing_keys::Column::RetiredAt.is_null())
            .filter(saml_signing_keys::Column::ValidFrom.lte(now.naive_utc()))
            .filter(saml_signing_keys::Column::ValidUntil.gt(now.naive_utc()))
            .order_by_desc(saml_signing_keys::Column::CreatedAt)
            .order_by_desc(saml_signing_keys::Column::Id)
            .one(&db)
            .await?;

        Ok(key)
    }

    /// Return the active certificate followed by at most the bounded set of
    /// previous certificates still inside their rollover publication window.
    pub async fn find_published_verification_keys_at(
        db: DB<'_>,
        service_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<saml_signing_keys::Model>> {
        let now = now.naive_utc();
        let mut keys = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::RetiredAt.is_null())
            .filter(saml_signing_keys::Column::ValidFrom.lte(now))
            .filter(saml_signing_keys::Column::ValidUntil.gt(now))
            .filter(
                Condition::any()
                    .add(saml_signing_keys::Column::IsActive.eq(true))
                    .add(
                        Condition::all()
                            .add(saml_signing_keys::Column::IsActive.eq(false))
                            .add(saml_signing_keys::Column::PublishUntil.gt(now)),
                    ),
            )
            .order_by_desc(saml_signing_keys::Column::CreatedAt)
            .order_by_desc(saml_signing_keys::Column::Id)
            .all(&db)
            .await?;

        keys.retain(|key| {
            key.is_active
                || key
                    .publish_until
                    .is_some_and(|publish_until| publish_until > now)
        });
        keys.sort_by(|left, right| {
            right
                .is_active
                .cmp(&left.is_active)
                .then_with(|| right.created_at.cmp(&left.created_at))
                .then_with(|| right.id.cmp(&left.id))
        });

        let mut active_seen = false;
        let mut previous_seen = 0;
        keys.retain(|key| {
            if key.is_active {
                if active_seen {
                    return false;
                }
                active_seen = true;
                true
            } else if previous_seen < MAX_PUBLISHED_PREVIOUS_CERTIFICATES {
                previous_seen += 1;
                true
            } else {
                false
            }
        });
        Ok(keys)
    }

    /// Promote a new active signing key and place the former active key into a
    /// bounded verification-only publication window. The caller must hold the
    /// service-row lock and execute this method inside the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn rotate_with_overlap(
        db: DB<'_>,
        id: &str,
        service_id: &str,
        private_key_encrypted: Vec<u8>,
        public_key: &str,
        encryption_key_id: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        now: DateTime<Utc>,
        overlap_until: DateTime<Utc>,
    ) -> Result<saml_signing_keys::Model> {
        // PostgreSQL and SQLite also enforce one active key with an index.
        // MySQL relies on the caller's service-row lock; loading and
        // deactivating every active row here heals legacy or externally-created
        // duplicates deterministically on the next rotation.
        let active_keys = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(true))
            .order_by_desc(saml_signing_keys::Column::CreatedAt)
            .order_by_desc(saml_signing_keys::Column::Id)
            .all(&db)
            .await?;
        let canonical_previous = active_keys.first().cloned();
        if !active_keys.is_empty() {
            let result = SamlSigningKeys::update_many()
                .col_expr(saml_signing_keys::Column::IsActive, Expr::value(false))
                .col_expr(
                    saml_signing_keys::Column::PublishUntil,
                    Expr::value(Some(now.naive_utc())),
                )
                .col_expr(
                    saml_signing_keys::Column::RetiredAt,
                    Expr::value(Some(now.naive_utc())),
                )
                .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
                .filter(saml_signing_keys::Column::IsActive.eq(true))
                .exec(&db)
                .await?;
            if result.rows_affected != active_keys.len() as u64 {
                return Err(AppError::ServiceUnavailable(
                    "SAML certificate rotation conflicted; retry the request".to_string(),
                ));
            }

            if let Some(previous) = canonical_previous {
                let publish_until = previous.valid_until.min(overlap_until.naive_utc());
                SamlSigningKeys::update_many()
                    .col_expr(
                        saml_signing_keys::Column::PublishUntil,
                        Expr::value(Some(publish_until)),
                    )
                    .col_expr(
                        saml_signing_keys::Column::RetiredAt,
                        Expr::value(Option::<chrono::NaiveDateTime>::None),
                    )
                    .filter(saml_signing_keys::Column::Id.eq(previous.id))
                    .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
                    .filter(saml_signing_keys::Column::IsActive.eq(false))
                    .exec(&db)
                    .await?;
            }
        }
        let key = Self::create(
            db.clone(),
            id,
            service_id,
            private_key_encrypted,
            public_key,
            encryption_key_id,
            valid_from,
            valid_until,
            true,
        )
        .await?;

        let excess_ids: Vec<String> = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(false))
            .filter(saml_signing_keys::Column::RetiredAt.is_null())
            .filter(saml_signing_keys::Column::PublishUntil.gt(now.naive_utc()))
            .filter(saml_signing_keys::Column::ValidUntil.gt(now.naive_utc()))
            .order_by_desc(saml_signing_keys::Column::CreatedAt)
            .order_by_desc(saml_signing_keys::Column::Id)
            .all(&db)
            .await?
            .into_iter()
            .skip(MAX_PUBLISHED_PREVIOUS_CERTIFICATES)
            .map(|key| key.id)
            .collect();
        if !excess_ids.is_empty() {
            SamlSigningKeys::update_many()
                .col_expr(
                    saml_signing_keys::Column::RetiredAt,
                    Expr::value(Some(now.naive_utc())),
                )
                .col_expr(
                    saml_signing_keys::Column::PublishUntil,
                    Expr::value(Some(now.naive_utc())),
                )
                .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
                .filter(saml_signing_keys::Column::Id.is_in(excess_ids))
                .exec(&db)
                .await?;
        }

        Ok(key)
    }

    /// Immediately remove every previous certificate from metadata while
    /// preserving the active signing key.
    pub async fn retire_overlaps_for_service(
        db: DB<'_>,
        service_id: &str,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let result = SamlSigningKeys::update_many()
            .col_expr(
                saml_signing_keys::Column::RetiredAt,
                Expr::value(Some(now.naive_utc())),
            )
            .col_expr(
                saml_signing_keys::Column::PublishUntil,
                Expr::value(Some(now.naive_utc())),
            )
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .filter(saml_signing_keys::Column::IsActive.eq(false))
            .filter(saml_signing_keys::Column::RetiredAt.is_null())
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Retire all key material when SAML is deleted for a service.
    pub async fn retire_all_for_service(
        db: DB<'_>,
        service_id: &str,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let result = SamlSigningKeys::update_many()
            .col_expr(saml_signing_keys::Column::IsActive, Expr::value(false))
            .col_expr(
                saml_signing_keys::Column::RetiredAt,
                Expr::value(Some(now.naive_utc())),
            )
            .col_expr(
                saml_signing_keys::Column::PublishUntil,
                Expr::value(Some(now.naive_utc())),
            )
            .filter(saml_signing_keys::Column::ServiceId.eq(service_id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Create a new signing key
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        id: &str,
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
            id: Set(id.to_string()),
            service_id: Set(service_id.to_string()),
            private_key_encrypted: Set(private_key_encrypted),
            public_key: Set(public_key.to_string()),
            encryption_key_id: Set(encryption_key_id.to_string()),
            valid_from: Set(valid_from.naive_utc()),
            valid_until: Set(valid_until.naive_utc()),
            is_active: Set(is_active),
            publish_until: Set(None),
            retired_at: Set(None),
            created_at: Set(now),
        };

        let key = new_key.insert(&db).await?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "db_sqlite")]
    use crate::error::with_retrying_transaction;
    use crate::store::services::ServiceStore;
    use migration::{Migrator, MigratorTrait};
    #[cfg(feature = "db_sqlite")]
    use sea_orm::QuerySelect;
    use sea_orm::{ConnectionTrait, Database};

    async fn setup() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db.execute_unprepared("PRAGMA foreign_keys = OFF")
            .await
            .expect("disable foreign keys for isolated store fixture");
        let _service = ServiceStore::create(
            DB::Conn(&db),
            "test-org",
            "saml-service",
            "SAML Service",
            "web",
            "saml-client",
        )
        .await
        .expect("create service");
        db
    }

    async fn create_key(
        db: &sea_orm::DatabaseConnection,
        id: &str,
        service_id: &str,
        is_active: bool,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> saml_signing_keys::Model {
        SamlSigningKeysStore::create(
            DB::Conn(db),
            id,
            service_id,
            vec![1, 2, 3],
            &format!("certificate-{id}"),
            "test-encryption-key",
            valid_from,
            valid_until,
            is_active,
        )
        .await
        .expect("create signing key")
    }

    async fn service_id(db: &sea_orm::DatabaseConnection) -> String {
        ServiceStore::find_by_org_and_slug(DB::Conn(db), "test-org", "saml-service")
            .await
            .expect("find service")
            .expect("service exists")
            .id
    }

    #[tokio::test]
    async fn rotation_publishes_previous_but_signs_only_with_active_and_retires_idempotently() {
        let db = setup().await;
        let service_id = service_id(&db).await;
        let now = Utc::now();
        create_key(
            &db,
            "old",
            &service_id,
            true,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(365),
        )
        .await;

        SamlSigningKeysStore::rotate_with_overlap(
            DB::Conn(&db),
            "new",
            &service_id,
            vec![4, 5, 6],
            "certificate-new",
            "test-encryption-key",
            now,
            now + chrono::Duration::days(365),
            now,
            now + chrono::Duration::days(SAML_CERTIFICATE_OVERLAP_DAYS),
        )
        .await
        .expect("rotate key");

        let signer = SamlSigningKeysStore::find_signing_key_by_service_at(
            DB::Conn(&db),
            &service_id,
            now + chrono::Duration::seconds(1),
        )
        .await
        .expect("find signer")
        .expect("signer exists");
        assert_eq!(signer.id, "new");

        let published = SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now + chrono::Duration::seconds(1),
        )
        .await
        .expect("find published keys");
        assert_eq!(
            published
                .iter()
                .map(|key| key.id.as_str())
                .collect::<Vec<_>>(),
            vec!["new", "old"]
        );
        assert!(!published[1].is_active);

        assert_eq!(
            SamlSigningKeysStore::retire_overlaps_for_service(
                DB::Conn(&db),
                &service_id,
                now + chrono::Duration::minutes(1),
            )
            .await
            .expect("retire overlap"),
            1
        );
        assert_eq!(
            SamlSigningKeysStore::retire_overlaps_for_service(
                DB::Conn(&db),
                &service_id,
                now + chrono::Duration::minutes(1),
            )
            .await
            .expect("repeat retirement"),
            0
        );
        let published = SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now + chrono::Duration::minutes(1),
        )
        .await
        .expect("find post-retirement keys");
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].id, "new");
    }

    #[cfg(feature = "db_sqlite")]
    #[tokio::test]
    async fn duplicate_active_keys_are_selected_consistently_and_healed_on_rotation() {
        let db = setup().await;
        let service_id = service_id(&db).await;
        let now = Utc::now();
        db.execute_unprepared("DROP INDEX idx_saml_keys_service_active_unique")
            .await
            .expect("allow legacy duplicate fixture");
        create_key(
            &db,
            "duplicate-a",
            &service_id,
            true,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(365),
        )
        .await;
        create_key(
            &db,
            "duplicate-z",
            &service_id,
            true,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(365),
        )
        .await;
        let same_created_at = now.naive_utc();
        SamlSigningKeys::update_many()
            .col_expr(
                saml_signing_keys::Column::CreatedAt,
                Expr::value(same_created_at),
            )
            .filter(saml_signing_keys::Column::ServiceId.eq(&service_id))
            .exec(&db)
            .await
            .expect("align duplicate timestamps");

        let signer =
            SamlSigningKeysStore::find_signing_key_by_service_at(DB::Conn(&db), &service_id, now)
                .await
                .expect("query signer")
                .expect("signer exists");
        let published = SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now,
        )
        .await
        .expect("query metadata keys");
        assert_eq!(signer.id, "duplicate-z");
        assert_eq!(published[0].id, signer.id);
        assert_eq!(published.iter().filter(|key| key.is_active).count(), 1);

        SamlSigningKeysStore::rotate_with_overlap(
            DB::Conn(&db),
            "replacement",
            &service_id,
            vec![9],
            "certificate-replacement",
            "test-encryption-key",
            now,
            now + chrono::Duration::days(365),
            now,
            now + chrono::Duration::days(SAML_CERTIFICATE_OVERLAP_DAYS),
        )
        .await
        .expect("heal duplicate actives while rotating");

        let keys = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(&service_id))
            .all(&db)
            .await
            .expect("list healed keys");
        assert_eq!(keys.iter().filter(|key| key.is_active).count(), 1);
        let replacement = keys
            .iter()
            .find(|key| key.id == "replacement")
            .expect("replacement exists");
        let canonical_previous = keys
            .iter()
            .find(|key| key.id == "duplicate-z")
            .expect("canonical previous exists");
        let discarded_duplicate = keys
            .iter()
            .find(|key| key.id == "duplicate-a")
            .expect("discarded duplicate exists");
        assert!(replacement.is_active);
        assert!(!canonical_previous.is_active);
        assert!(canonical_previous.retired_at.is_none());
        assert!(!discarded_duplicate.is_active);
        assert!(discarded_duplicate.retired_at.is_some());
    }

    #[tokio::test]
    async fn overlap_expiry_and_repeated_rotations_remain_bounded() {
        let db = setup().await;
        let service_id = service_id(&db).await;
        let now = Utc::now();
        create_key(
            &db,
            "key-0",
            &service_id,
            true,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(365),
        )
        .await;
        for index in 1..=4 {
            SamlSigningKeysStore::rotate_with_overlap(
                DB::Conn(&db),
                &format!("key-{index}"),
                &service_id,
                vec![index as u8],
                &format!("certificate-{index}"),
                "test-encryption-key",
                now,
                now + chrono::Duration::days(365),
                now,
                now + chrono::Duration::days(SAML_CERTIFICATE_OVERLAP_DAYS),
            )
            .await
            .expect("rotate key");
        }

        let published = SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now + chrono::Duration::seconds(1),
        )
        .await
        .expect("find bounded keys");
        assert_eq!(published.len(), 1 + MAX_PUBLISHED_PREVIOUS_CERTIFICATES);
        assert_eq!(published.iter().filter(|key| key.is_active).count(), 1);

        let after_overlap = SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now + chrono::Duration::days(SAML_CERTIFICATE_OVERLAP_DAYS + 1),
        )
        .await
        .expect("find expired overlap keys");
        assert_eq!(after_overlap.len(), 1);
        assert!(after_overlap[0].is_active);
    }

    #[cfg(feature = "db_sqlite")]
    #[tokio::test]
    async fn concurrent_rotations_leave_one_active_and_a_bounded_overlap_set() {
        let db = setup().await;
        let service_id = service_id(&db).await;
        let now = Utc::now();
        create_key(
            &db,
            "original",
            &service_id,
            true,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(365),
        )
        .await;

        let rotate = |id: &'static str| {
            let db = db.clone();
            let service_id = service_id.clone();
            async move {
                with_retrying_transaction(&db, &db, "test_saml_rotation", |tx| {
                    let service_id = service_id.clone();
                    Box::pin(async move {
                        let _lock = crate::entities::services::Entity::find_by_id(&service_id)
                            .lock_exclusive()
                            .one(&tx)
                            .await?
                            .expect("service exists");
                        SamlSigningKeysStore::rotate_with_overlap(
                            tx,
                            id,
                            &service_id,
                            vec![9],
                            &format!("certificate-{id}"),
                            "test-encryption-key",
                            now,
                            now + chrono::Duration::days(365),
                            now,
                            now + chrono::Duration::days(SAML_CERTIFICATE_OVERLAP_DAYS),
                        )
                        .await
                    })
                })
                .await
            }
        };
        let (first, second) = tokio::join!(rotate("concurrent-a"), rotate("concurrent-b"));
        first.expect("first rotation");
        second.expect("second rotation");

        let all = SamlSigningKeys::find()
            .filter(saml_signing_keys::Column::ServiceId.eq(&service_id))
            .all(&db)
            .await
            .expect("list keys");
        assert_eq!(all.iter().filter(|key| key.is_active).count(), 1);
        let published = SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now + chrono::Duration::seconds(1),
        )
        .await
        .expect("find published keys");
        assert!(published.len() <= 1 + MAX_PUBLISHED_PREVIOUS_CERTIFICATES);
    }

    #[tokio::test]
    async fn retiring_all_removes_active_and_overlap_material_from_use() {
        let db = setup().await;
        let service_id = service_id(&db).await;
        let now = Utc::now();
        create_key(
            &db,
            "old",
            &service_id,
            true,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(365),
        )
        .await;
        SamlSigningKeysStore::rotate_with_overlap(
            DB::Conn(&db),
            "new",
            &service_id,
            vec![4],
            "certificate-new",
            "test-encryption-key",
            now,
            now + chrono::Duration::days(365),
            now,
            now + chrono::Duration::days(SAML_CERTIFICATE_OVERLAP_DAYS),
        )
        .await
        .expect("rotate key");

        assert_eq!(
            SamlSigningKeysStore::retire_all_for_service(DB::Conn(&db), &service_id, now)
                .await
                .expect("retire all"),
            2
        );
        assert!(SamlSigningKeysStore::find_signing_key_by_service_at(
            DB::Conn(&db),
            &service_id,
            now
        )
        .await
        .expect("query signer")
        .is_none());
        assert!(SamlSigningKeysStore::find_published_verification_keys_at(
            DB::Conn(&db),
            &service_id,
            now
        )
        .await
        .expect("query metadata keys")
        .is_empty());
    }
}
