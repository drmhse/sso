use crate::error::{AppError, Result};
use crate::store::{
    login_events::LoginEventStore, organization_tiers::OrganizationTierStore,
    organizations::OrganizationStore, DB,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TierFeatures {
    #[serde(default)]
    pub allow_custom_domain: bool,
    #[serde(default)]
    pub allow_saml_idp: bool,
    #[serde(default)]
    pub allow_scim: bool,
    #[serde(default)]
    pub allow_siem: bool,
    #[serde(default)]
    pub allow_branding: bool,
    #[serde(default)]
    pub allow_passkeys: bool,
    #[serde(default)]
    pub allowed_social_providers: Vec<String>,
    #[serde(default)]
    pub max_mau: i64,
    /// If true, exceeding MAU limit will log a warning but not block logins
    #[serde(default)]
    pub allow_overage: bool,
}

pub struct TierService;

impl TierService {
    /// Checks if an organization has access to a specific feature
    pub async fn check_feature_access(
        db: DB<'_>,
        org_id: &str,
        check: impl Fn(&TierFeatures) -> bool,
        feature_name: &str,
    ) -> Result<()> {
        // 1. Fetch Org
        let org = OrganizationStore::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        // 2. Check Org-specific overrides FIRST
        if let Some(overrides) = &org.feature_overrides {
            // If parsing fails, we log/ignore and fall back to tier defaults?
            // Better to fail safe or log error. For now let's try to parse.
            if let Ok(org_features) = serde_json::from_str::<TierFeatures>(overrides) {
                if check(&org_features) {
                    return Ok(()); // Allow based on override
                }
            }
        }

        // 3. Fallback to Tier defaults
        let tier_id = org.tier_id.ok_or_else(|| {
            AppError::InternalServerError("Organization has no tier assigned".to_string())
        })?;

        let tier = OrganizationTierStore::find_by_id(db, &tier_id)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("Tier configuration missing".to_string())
            })?;

        // 4. Parse Features JSON
        let features: TierFeatures = serde_json::from_str(&tier.features.unwrap_or_default())
            .map_err(|_| AppError::InternalServerError("Invalid tier configuration".to_string()))?;

        // 5. Validate
        if !check(&features) {
            return Err(AppError::FeatureNotAvailableInTier(format!(
                "The feature '{}' is not available on your current plan. Please upgrade to access it.", 
                feature_name
            )));
        }

        Ok(())
    }

    /// Check MAU Limits (Billing Control)
    /// Returns Ok(()) if the organization is within its MAU limit or has allow_overage enabled.
    /// Returns Err(ServiceLimitExceeded) if the limit is exceeded and overage is not allowed.
    pub async fn check_mau_limit(db: DB<'_>, org_id: &str) -> Result<()> {
        // 1. Fetch organization
        let org = OrganizationStore::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        // 2. Determine MAU limit and allow_overage from org overrides or tier
        let (max_mau, allow_overage) = if let Some(overrides) = &org.feature_overrides {
            if let Ok(org_features) = serde_json::from_str::<TierFeatures>(overrides) {
                // If org has explicit max_mau override, use it
                if org_features.max_mau > 0 {
                    (org_features.max_mau, org_features.allow_overage)
                } else {
                    // Fall back to tier
                    Self::get_tier_mau_limit(db.clone(), &org.tier_id).await?
                }
            } else {
                Self::get_tier_mau_limit(db.clone(), &org.tier_id).await?
            }
        } else {
            Self::get_tier_mau_limit(db.clone(), &org.tier_id).await?
        };

        // 3. If max_mau is 0 or negative, it means unlimited
        if max_mau <= 0 {
            return Ok(());
        }

        // 4. Get current MAU count
        let current_mau = LoginEventStore::count_distinct_users_last_30_days(db, org_id).await?;

        // 5. Check if limit is exceeded
        if current_mau >= max_mau {
            if allow_overage {
                // Log the overage but allow the login
                tracing::warn!(
                    org_id = %org_id,
                    current_mau = current_mau,
                    max_mau = max_mau,
                    "Organization has exceeded MAU limit but overage is allowed"
                );
                return Ok(());
            }

            return Err(AppError::ServiceLimitExceeded(format!(
                "Monthly active user limit reached ({}/{}). Please upgrade your plan to continue.",
                current_mau, max_mau
            )));
        }

        Ok(())
    }

    /// Helper to get MAU limit from tier
    async fn get_tier_mau_limit(db: DB<'_>, tier_id: &Option<String>) -> Result<(i64, bool)> {
        let tier_id = tier_id.as_ref().ok_or_else(|| {
            AppError::InternalServerError("Organization has no tier assigned".to_string())
        })?;

        let tier = OrganizationTierStore::find_by_id(db, tier_id)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("Tier configuration missing".to_string())
            })?;

        let features: TierFeatures = serde_json::from_str(&tier.features.unwrap_or_default())
            .unwrap_or_else(|_| TierFeatures {
                allow_custom_domain: false,
                allow_saml_idp: false,
                allow_scim: false,
                allow_siem: false,
                allow_branding: false,
                allow_passkeys: false,
                allowed_social_providers: vec![],
                max_mau: 0,
                allow_overage: false,
            });

        Ok((features.max_mau, features.allow_overage))
    }
}
