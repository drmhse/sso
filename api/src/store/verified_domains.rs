use crate::entities::prelude::VerifiedDomains;
use crate::entities::verified_domains;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct VerifiedDomainStore;

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
    ) -> Result<verified_domains::Model> {
        let now = chrono::Utc::now().naive_utc();

        let domain_record = verified_domains::ActiveModel {
            id: Set(id.to_string()),
            org_id: Set(org_id.to_string()),
            domain: Set(domain.to_string()),
            upstream_provider_id: Set(upstream_provider_id.map(|s| s.to_string())),
            verification_token: Set(verification_token.to_string()),
            verified: Set(false),
            verified_at: Set(None),
            created_at: Set(now.clone()),
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
        domain.verified_at = Set(Some(now.clone()));
        domain.updated_at = Set(now);

        let result = domain.update(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to update domain: {}", e))
        })?;

        Ok(result)
    }

    /// Delete a domain verification record
    pub async fn delete(db: DB<'_>, domain_id: &str) -> Result<()> {
        let domain = VerifiedDomains::find_by_id(domain_id)
            .one(&db)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Domain not found".to_string()))?;

        let domain: verified_domains::ActiveModel = domain.into();
        domain.delete(&db).await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to delete domain: {}", e))
        })?;

        Ok(())
    }
}
