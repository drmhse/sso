use crate::db::DB;
use crate::entities::prelude::VerifiedDomains;
use crate::entities::verified_domains;
use crate::error::{AppError, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct VerifiedDomainStore;

pub const DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED: &str = "password_allowed";
pub const DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY: &str = "upstream_only";
pub const DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE: &str =
    "password_fallback_if_provider_unavailable";

impl VerifiedDomainStore {
    /// Find a verified domain by domain name
    pub async fn find_by_domain(
        db: DB<'_>,
        domain: &str,
    ) -> Result<Option<verified_domains::Model>> {
        let result = VerifiedDomains::find()
            .filter(verified_domains::Column::Domain.eq(domain))
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(result)
    }

    pub async fn find_verified_by_email_domain(
        db: DB<'_>,
        email: &str,
    ) -> Result<Option<verified_domains::Model>> {
        let domain = email
            .split('@')
            .nth(1)
            .map(str::trim)
            .map(str::to_lowercase);

        let Some(domain) = domain.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };

        Ok(Self::find_by_domain(db, &domain)
            .await?
            .filter(|domain| domain.verified))
    }

    /// Find all verified domains for an organization
    pub async fn find_by_org(db: DB<'_>, org_id: &str) -> Result<Vec<verified_domains::Model>> {
        let results = VerifiedDomains::find()
            .filter(verified_domains::Column::OrgId.eq(org_id))
            .all(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(results)
    }

    /// Create a new domain verification record
    pub async fn create(
        db: DB<'_>,
        id: &str,
        org_id: &str,
        domain: &str,
        verification_token: &str,
        upstream_provider_id: Option<&str>,
        login_policy: Option<&str>,
    ) -> Result<verified_domains::Model> {
        let now = chrono::Utc::now().naive_utc();

        let domain_record = verified_domains::ActiveModel {
            id: Set(id.to_string()),
            org_id: Set(org_id.to_string()),
            domain: Set(domain.to_string()),
            upstream_provider_id: Set(upstream_provider_id.map(std::string::ToString::to_string)),
            login_policy: Set(login_policy
                .unwrap_or(DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED)
                .to_string()),
            verification_token: Set(verification_token.to_string()),
            verified: Set(false),
            verified_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let result = domain_record.insert(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to create domain: {}", e))
        })?;

        Ok(result)
    }

    /// Mark a domain as verified
    pub async fn mark_verified(db: DB<'_>, domain_id: &str) -> Result<verified_domains::Model> {
        let now = chrono::Utc::now().naive_utc();

        let domain = VerifiedDomains::find_by_id(domain_id)
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Domain not found".to_string()))?;

        let mut domain: verified_domains::ActiveModel = domain.into();
        domain.verified = Set(true);
        domain.verified_at = Set(Some(now));
        domain.updated_at = Set(now);

        let result = domain.update(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to update domain: {}", e))
        })?;

        Ok(result)
    }

    /// Mark a domain verified only when it belongs to the selected organization.
    pub async fn mark_verified_in_org(
        db: DB<'_>,
        org_id: &str,
        domain_id: &str,
    ) -> Result<verified_domains::Model> {
        let now = chrono::Utc::now().naive_utc();
        let result = VerifiedDomains::update_many()
            .filter(verified_domains::Column::Id.eq(domain_id))
            .filter(verified_domains::Column::OrgId.eq(org_id))
            .col_expr(
                verified_domains::Column::Verified,
                sea_orm::sea_query::Expr::value(true),
            )
            .col_expr(
                verified_domains::Column::VerifiedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .col_expr(
                verified_domains::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .exec(&db)
            .await
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to update domain: {}", e))
            })?;

        if result.rows_affected != 1 {
            return Err(AppError::NotFound("Domain not found".to_string()));
        }

        VerifiedDomains::find()
            .filter(verified_domains::Column::Id.eq(domain_id))
            .filter(verified_domains::Column::OrgId.eq(org_id))
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Domain not found".to_string()))
    }

    /// Delete a domain verification record
    pub async fn delete_in_org(db: DB<'_>, org_id: &str, domain_id: &str) -> Result<bool> {
        let result = VerifiedDomains::delete_many()
            .filter(verified_domains::Column::Id.eq(domain_id))
            .filter(verified_domains::Column::OrgId.eq(org_id))
            .exec(&db)
            .await
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to delete domain: {}", e))
            })?;

        Ok(result.rows_affected == 1)
    }
}
