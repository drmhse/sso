use crate::entities::{organizations, prelude::ScimTokens, scim_tokens};
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait,
    Set,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct ScimTokenStore;

impl ScimTokenStore {
    /// Generate a new SCIM token
    /// Returns (full_token, prefix, hash)
    pub fn generate() -> (String, String, String) {
        let random_part = Uuid::new_v4().to_string().replace('-', "");
        let full_token = format!("scim_{}", random_part);
        let prefix = full_token.chars().take(8).collect::<String>();
        let hash = Self::hash_token(&full_token);

        (full_token, prefix, hash)
    }

    /// Hash a SCIM token using SHA256
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Create a new SCIM token
    pub async fn create(
        db: DB<'_>,
        org_id: &str,
        name: &str,
        token_hash: &str,
        prefix: &str,
        created_by: &str,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<scim_tokens::Model> {
        let token = scim_tokens::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            name: Set(name.to_string()),
            token_hash: Set(token_hash.to_string()),
            prefix: Set(prefix.to_string()),
            active: Set(true),
            expires_at: Set(expires_at),
            last_used_at: Set(None),
            created_by: Set(created_by.to_string()),
            created_at: Set(Utc::now().naive_utc()),
        };

        let result = token.insert(&db).await?;
        Ok(result)
    }

    /// Find a SCIM token by hash
    pub async fn find_by_hash(db: DB<'_>, token_hash: &str) -> Result<Option<scim_tokens::Model>> {
        let token = ScimTokens::find()
            .filter(scim_tokens::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;

        Ok(token)
    }

    /// Find a SCIM token by ID.
    pub async fn find_by_id(db: DB<'_>, token_id: &str) -> Result<Option<scim_tokens::Model>> {
        let token = ScimTokens::find()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .one(&db)
            .await?;

        Ok(token)
    }

    /// List all SCIM tokens for an organization
    pub async fn list_by_org(db: DB<'_>, org_id: &str) -> Result<Vec<scim_tokens::Model>> {
        let tokens = ScimTokens::find()
            .filter(scim_tokens::Column::OrgId.eq(org_id))
            .all(&db)
            .await?;

        Ok(tokens)
    }

    /// Update last_used_at timestamp
    pub async fn update_last_used(db: DB<'_>, token_id: &str) -> Result<()> {
        ScimTokens::update_many()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .col_expr(
                scim_tokens::Column::LastUsedAt,
                Expr::value(Some(Utc::now().naive_utc())),
            )
            .exec(&db)
            .await?;

        Ok(())
    }

    /// Revoke a SCIM token (set active = false)
    pub async fn revoke_in_org(db: DB<'_>, org_id: &str, token_id: &str) -> Result<bool> {
        let result = ScimTokens::update_many()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .filter(scim_tokens::Column::OrgId.eq(org_id))
            .col_expr(scim_tokens::Column::Active, Expr::value(false))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Delete a SCIM token permanently
    pub async fn delete_in_org(db: DB<'_>, org_id: &str, token_id: &str) -> Result<bool> {
        let result = ScimTokens::delete_many()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .filter(scim_tokens::Column::OrgId.eq(org_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Verify a SCIM token is valid (active and not expired)
    pub async fn verify(db: DB<'_>, token: &str) -> Result<Option<scim_tokens::Model>> {
        let token_hash = Self::hash_token(token);
        let scim_token = Self::find_by_hash(db, &token_hash).await?;

        if let Some(ref t) = scim_token {
            // Check if active
            if !t.active {
                return Ok(None);
            }

            // Check if expired
            if let Some(expires_at) = t.expires_at {
                let expires = chrono::DateTime::<Utc>::from_naive_utc_and_offset(expires_at, Utc);
                if expires < Utc::now() {
                    return Ok(None);
                }
            }
        }

        Ok(scim_token)
    }

    /// Verify a SCIM token and its live parent organization in one query.
    /// Suspended, rejected, or otherwise inactive organizations cannot use a
    /// previously issued token.
    pub async fn verify_for_active_org(
        db: DB<'_>,
        token: &str,
    ) -> Result<Option<scim_tokens::Model>> {
        let token_hash = Self::hash_token(token);
        let scim_token = ScimTokens::find()
            .join(
                JoinType::InnerJoin,
                scim_tokens::Relation::Organization.def(),
            )
            .filter(scim_tokens::Column::TokenHash.eq(token_hash))
            .filter(scim_tokens::Column::Active.eq(true))
            .filter(organizations::Column::Status.eq("active"))
            .one(&db)
            .await?;

        if let Some(ref token) = scim_token {
            if token
                .expires_at
                .is_some_and(|expires_at| expires_at < Utc::now().naive_utc())
            {
                return Ok(None);
            }
        }

        Ok(scim_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{organizations, users};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, DatabaseConnection};

    async fn insert_user(db: &DatabaseConnection) -> String {
        let user_id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();
        users::ActiveModel {
            id: Set(user_id.clone()),
            email: Set(format!("{user_id}@example.com")),
            org_id: Set(None),
            is_platform_owner: Set(false),
            password_hash: Set(None),
            email_verified_at: Set(None),
            created_at: Set(now),
            updated_at: Set(None),
            deleted_at: Set(None),
        }
        .insert(db)
        .await
        .expect("insert user");

        user_id
    }

    async fn insert_org(db: &DatabaseConnection, owner_user_id: &str) -> String {
        let org_id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();
        organizations::ActiveModel {
            id: Set(org_id.clone()),
            slug: Set(format!("org-{}", &org_id[..8])),
            name: Set("Test Org".to_string()),
            owner_user_id: Set(owner_user_id.to_string()),
            status: Set("active".to_string()),
            tier_id: Set(None),
            max_services: Set(None),
            max_users: Set(None),
            approved_by: Set(None),
            approved_at: Set(None),
            rejected_by: Set(None),
            rejected_at: Set(None),
            rejection_reason: Set(None),
            smtp_host: Set(None),
            smtp_port: Set(None),
            smtp_username: Set(None),
            smtp_password_encrypted: Set(None),
            smtp_from_email: Set(None),
            smtp_from_name: Set(None),
            smtp_encryption_key_id: Set(None),
            custom_domain: Set(None),
            domain_verified: Set(false),
            domain_verification_token: Set(None),
            brand_logo_url: Set(None),
            brand_primary_color: Set(None),
            feature_overrides: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await
        .expect("insert org");

        org_id
    }

    async fn setup_db() -> (DatabaseConnection, String, String) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user_id = insert_user(&db).await;
        let org_id = insert_org(&db, &user_id).await;
        (db, org_id, user_id)
    }

    #[tokio::test]
    async fn scim_token_mutations_do_not_preload_rows() {
        let (db, org_id, user_id) = setup_db().await;
        let (_, prefix, hash) = ScimTokenStore::generate();
        let token = ScimTokenStore::create(
            DB::Conn(&db),
            &org_id,
            "Okta",
            &hash,
            &prefix,
            &user_id,
            None,
        )
        .await
        .expect("create token");

        ScimTokenStore::update_last_used(DB::Conn(&db), &token.id)
            .await
            .expect("update last used");
        let used = ScimTokenStore::find_by_id(DB::Conn(&db), &token.id)
            .await
            .expect("load token")
            .expect("token exists");
        assert!(used.last_used_at.is_some());

        ScimTokenStore::revoke_in_org(DB::Conn(&db), &org_id, &token.id)
            .await
            .expect("revoke token");
        let revoked = ScimTokenStore::find_by_id(DB::Conn(&db), &token.id)
            .await
            .expect("load revoked token")
            .expect("token exists");
        assert!(!revoked.active);

        ScimTokenStore::delete_in_org(DB::Conn(&db), &org_id, &token.id)
            .await
            .expect("delete token");
        assert!(ScimTokenStore::find_by_id(DB::Conn(&db), &token.id)
            .await
            .expect("load deleted token")
            .is_none());
    }

    #[tokio::test]
    async fn scim_token_missing_mutations_remain_noops() {
        let (db, _, _) = setup_db().await;
        let missing_id = Uuid::new_v4().to_string();

        ScimTokenStore::update_last_used(DB::Conn(&db), &missing_id)
            .await
            .expect("missing last-used update is a noop");
        ScimTokenStore::revoke_in_org(DB::Conn(&db), "missing-org", &missing_id)
            .await
            .expect("missing revoke is a noop");
        ScimTokenStore::delete_in_org(DB::Conn(&db), "missing-org", &missing_id)
            .await
            .expect("missing delete is a noop");
    }

    #[tokio::test]
    async fn scim_token_lifecycle_is_org_scoped_and_preserves_other_tenant() {
        let (db, org_a, user_id) = setup_db().await;
        let org_b = insert_org(&db, &user_id).await;
        let (_, prefix, hash) = ScimTokenStore::generate();
        let token = ScimTokenStore::create(
            DB::Conn(&db),
            &org_b,
            "Other tenant token",
            &hash,
            &prefix,
            &user_id,
            None,
        )
        .await
        .expect("create other tenant token");

        assert!(
            !ScimTokenStore::revoke_in_org(DB::Conn(&db), &org_a, &token.id)
                .await
                .expect("cross-org revoke is a noop")
        );
        assert!(
            ScimTokenStore::find_by_id(DB::Conn(&db), &token.id)
                .await
                .expect("load preserved token")
                .expect("token remains")
                .active
        );

        assert!(
            !ScimTokenStore::delete_in_org(DB::Conn(&db), &org_a, &token.id)
                .await
                .expect("cross-org delete is a noop")
        );
        assert!(ScimTokenStore::find_by_id(DB::Conn(&db), &token.id)
            .await
            .expect("load preserved token")
            .is_some());

        assert!(
            ScimTokenStore::revoke_in_org(DB::Conn(&db), &org_b, &token.id)
                .await
                .expect("same-org revoke")
        );
        assert!(
            ScimTokenStore::delete_in_org(DB::Conn(&db), &org_b, &token.id)
                .await
                .expect("same-org delete")
        );
    }
}
