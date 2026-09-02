use crate::db::DB;
use crate::entities::prelude::WebauthnChallenges;
use crate::entities::webauthn_challenges;
use crate::error::Result;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct WebAuthnChallengeStore;

impl WebAuthnChallengeStore {
    /// Create a new WebAuthn challenge
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        challenge_type: &str,
        challenge_state: &str,
        expires_in_seconds: i64,
    ) -> Result<webauthn_challenges::Model> {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(expires_in_seconds);

        let challenge = webauthn_challenges::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            challenge_type: Set(challenge_type.to_string()),
            challenge_state: Set(challenge_state.to_string()),
            created_at: Set(now.naive_utc()),
            expires_at: Set(expires_at.naive_utc()),
        };

        let result = challenge.insert(&db).await?;
        Ok(result)
    }

    /// Find a challenge by ID (excludes expired challenges)
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<webauthn_challenges::Model>> {
        let now = Utc::now().naive_utc();

        let result = WebauthnChallenges::find()
            .filter(webauthn_challenges::Column::Id.eq(id))
            .filter(webauthn_challenges::Column::ExpiresAt.gt(now))
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Delete a challenge by ID
    pub async fn delete(db: DB<'_>, id: &str) -> Result<bool> {
        let result = WebauthnChallenges::delete_many()
            .filter(webauthn_challenges::Column::Id.eq(id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Delete expired challenges (cleanup job)
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = Utc::now().naive_utc();

        let result = WebauthnChallenges::delete_many()
            .filter(webauthn_challenges::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::users::UserStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn concurrent_challenge_consumption_has_exactly_one_winner() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "challenge@example.com", None, false)
            .await
            .expect("create user");
        let challenge = WebAuthnChallengeStore::create(
            DB::Conn(&db),
            &user.id,
            "authentication",
            "serialized-state",
            300,
        )
        .await
        .expect("create challenge");

        let first = WebAuthnChallengeStore::delete(DB::Conn(&db), &challenge.id);
        let second = WebAuthnChallengeStore::delete(DB::Conn(&db), &challenge.id);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            usize::from(first.expect("first consume"))
                + usize::from(second.expect("second consume")),
            1
        );
    }

    #[tokio::test]
    async fn expired_challenge_is_not_returned() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "expired-challenge@example.com", None, false)
            .await
            .expect("create user");
        let challenge = WebAuthnChallengeStore::create(
            DB::Conn(&db),
            &user.id,
            "authentication",
            "serialized-state",
            -1,
        )
        .await
        .expect("create expired challenge");

        assert!(
            WebAuthnChallengeStore::find_by_id(DB::Conn(&db), &challenge.id)
                .await
                .expect("find challenge")
                .is_none()
        );
    }
}
