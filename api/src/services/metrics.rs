//! MFA metrics collection and analysis service

use anyhow::Result;
use chrono::{Duration, Utc};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use crate::entities::{
    mfa_audit_log, mfa_daily_metrics, mfa_failure_patterns, mfa_feature_usage, user_totp_secrets,
    users,
};

/// MFA metrics aggregation result (matches mfa_daily_metrics entity)
#[derive(Debug, serde::Serialize)]
pub struct MfaMetricsSummary {
    pub org_id: Option<String>, // None = platform-wide
    pub date: String,
    pub total_users: i32,
    pub mfa_enabled_users: i32,
    pub new_mfa_setups: i32,
    pub mfa_disabled: i32,
    pub totp_verifications_total: i32,
    pub totp_verifications_success: i32,
    pub totp_verifications_failed: i32,
    pub backup_codes_generated: i32,
    pub backup_codes_used: i32,
}

/// Suspicious activity alert based on mfa_failure_patterns
#[derive(Debug, serde::Serialize)]
pub struct SuspiciousActivityAlert {
    pub id: String,
    pub org_id: Option<String>,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub ip_address: Option<String>,
    pub failure_type: String,
    pub failure_count: i32,
    pub is_suspicious: bool,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub details: Option<String>,
}

/// MFA feature usage event (matches mfa_feature_usage entity)
#[derive(Debug, serde::Serialize)]
pub struct MfaFeatureEvent {
    pub id: String,
    pub org_id: String,
    pub user_id: String,
    pub feature_type: String,
    pub timestamp: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub details: Option<String>,
}

/// MFA metrics service for collecting and analyzing MFA usage patterns
pub struct MfaMetricsService {
    db: DatabaseConnection,
}

impl MfaMetricsService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    // ========================================
    // MFA Feature Usage Recording
    // ========================================

    /// Record a MFA feature usage event
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub async fn record_feature_usage(
        &self,
        org_id: &str,
        user_id: &str,
        feature_type: &str, // "totp_setup", "totp_verify", "backup_code_used", etc.
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
        details: Option<&str>,
    ) -> Result<mfa_feature_usage::Model> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();

        let active_model = mfa_feature_usage::ActiveModel {
            id: Set(id),
            org_id: Set(org_id.to_string()),
            user_id: Set(user_id.to_string()),
            feature_type: Set(feature_type.to_string()),
            timestamp: Set(now),
            ip_address: Set(ip_address.map(|s| s.to_string())),
            user_agent: Set(user_agent.map(|s| s.to_string())),
            success: Set(success),
            details: Set(details.map(|s| s.to_string())),
        };

        let result = active_model.insert(&self.db).await?;
        Ok(result)
    }

    /// Get feature usage events for a user
    #[allow(dead_code)]
    pub async fn get_user_feature_usage(
        &self,
        user_id: &str,
        limit: Option<u64>,
    ) -> Result<Vec<MfaFeatureEvent>> {
        use sea_orm::QuerySelect;

        let limit_val = limit.unwrap_or(100);

        let events = mfa_feature_usage::Entity::find()
            .filter(mfa_feature_usage::Column::UserId.eq(user_id))
            .order_by_desc(mfa_feature_usage::Column::Timestamp)
            .limit(limit_val)
            .all(&self.db)
            .await?;

        Ok(events
            .into_iter()
            .map(|e| MfaFeatureEvent {
                id: e.id,
                org_id: e.org_id,
                user_id: e.user_id,
                feature_type: e.feature_type,
                timestamp: e.timestamp.to_string(),
                ip_address: e.ip_address,
                user_agent: e.user_agent,
                success: e.success,
                details: e.details,
            })
            .collect())
    }

    /// Get feature usage events for an organization
    #[allow(dead_code)]
    pub async fn get_org_feature_usage(
        &self,
        org_id: &str,
        limit: Option<u64>,
    ) -> Result<Vec<MfaFeatureEvent>> {
        use sea_orm::QuerySelect;

        let limit_val = limit.unwrap_or(100);

        let events = mfa_feature_usage::Entity::find()
            .filter(mfa_feature_usage::Column::OrgId.eq(org_id))
            .order_by_desc(mfa_feature_usage::Column::Timestamp)
            .limit(limit_val)
            .all(&self.db)
            .await?;

        Ok(events
            .into_iter()
            .map(|e| MfaFeatureEvent {
                id: e.id,
                org_id: e.org_id,
                user_id: e.user_id,
                feature_type: e.feature_type,
                timestamp: e.timestamp.to_string(),
                ip_address: e.ip_address,
                user_agent: e.user_agent,
                success: e.success,
                details: e.details,
            })
            .collect())
    }

    // ========================================
    // MFA Failure Pattern Tracking
    // ========================================

    /// Record a failure event and update failure patterns for suspicious activity detection
    #[allow(dead_code)]
    pub async fn record_failure(
        &self,
        org_id: Option<&str>,
        user_id: Option<&str>,
        ip_address: Option<&str>,
        failure_type: &str, // "invalid_totp", "expired_code", "rate_limited", etc.
        details: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().naive_utc();

        // Check if we have an existing pattern for this user/IP combination
        let mut query = mfa_failure_patterns::Entity::find()
            .filter(mfa_failure_patterns::Column::FailureType.eq(failure_type));

        if let Some(oid) = org_id {
            query = query.filter(mfa_failure_patterns::Column::OrgId.eq(oid));
        } else {
            query = query.filter(mfa_failure_patterns::Column::OrgId.is_null());
        }

        if let Some(uid) = user_id {
            query = query.filter(mfa_failure_patterns::Column::UserId.eq(uid));
        } else {
            query = query.filter(mfa_failure_patterns::Column::UserId.is_null());
        }

        if let Some(ip) = ip_address {
            query = query.filter(mfa_failure_patterns::Column::IpAddress.eq(ip));
        } else {
            query = query.filter(mfa_failure_patterns::Column::IpAddress.is_null());
        }

        let existing_pattern = query.one(&self.db).await?;

        if let Some(pattern) = existing_pattern {
            // Update existing pattern
            let new_count = pattern.failure_count + 1;
            let is_suspicious = new_count >= 5; // Mark as suspicious after 5 failures

            let mut active_pattern: mfa_failure_patterns::ActiveModel = pattern.into();
            active_pattern.failure_count = Set(new_count);
            active_pattern.last_seen_at = Set(now);
            active_pattern.is_suspicious = Set(is_suspicious);
            if details.is_some() {
                active_pattern.details = Set(details.map(|s| s.to_string()));
            }

            active_pattern.update(&self.db).await?;

            if is_suspicious {
                tracing::warn!(
                    "Suspicious MFA activity detected: org_id={:?}, user_id={:?}, ip={:?}, type={}, count={}",
                    org_id,
                    user_id,
                    ip_address,
                    failure_type,
                    new_count
                );
            }
        } else {
            // Create new pattern
            let pattern_id = Uuid::new_v4().to_string();

            let new_pattern = mfa_failure_patterns::ActiveModel {
                id: Set(pattern_id),
                org_id: Set(org_id.map(|s| s.to_string())),
                user_id: Set(user_id.map(|s| s.to_string())),
                ip_address: Set(ip_address.map(|s| s.to_string())),
                failure_type: Set(failure_type.to_string()),
                failure_count: Set(1),
                first_seen_at: Set(now),
                last_seen_at: Set(now),
                is_suspicious: Set(false),
                details: Set(details.map(|s| s.to_string())),
            };

            new_pattern.insert(&self.db).await?;
        }

        Ok(())
    }

    /// Clear failure patterns for a user (e.g., after successful verification)
    #[allow(dead_code)]
    pub async fn clear_user_failures(&self, user_id: &str) -> Result<u64> {
        use sea_orm::DeleteResult;

        let result: DeleteResult = mfa_failure_patterns::Entity::delete_many()
            .filter(mfa_failure_patterns::Column::UserId.eq(user_id))
            .exec(&self.db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Get suspicious activity for an organization
    #[allow(dead_code)]
    pub async fn get_suspicious_activity(
        &self,
        org_id: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<SuspiciousActivityAlert>> {
        use sea_orm::QuerySelect;

        let limit_val = limit.unwrap_or(100);

        let mut query = mfa_failure_patterns::Entity::find()
            .filter(mfa_failure_patterns::Column::IsSuspicious.eq(true));

        if let Some(oid) = org_id {
            query = query.filter(mfa_failure_patterns::Column::OrgId.eq(oid));
        }

        let patterns = query
            .order_by_desc(mfa_failure_patterns::Column::LastSeenAt)
            .limit(limit_val)
            .all(&self.db)
            .await?;

        // Fetch user emails for user_ids
        let user_ids: Vec<String> = patterns.iter().filter_map(|p| p.user_id.clone()).collect();

        let users_map: std::collections::HashMap<String, String> = if !user_ids.is_empty() {
            users::Entity::find()
                .filter(users::Column::Id.is_in(user_ids))
                .all(&self.db)
                .await?
                .into_iter()
                .map(|u| (u.id, u.email))
                .collect()
        } else {
            std::collections::HashMap::new()
        };

        Ok(patterns
            .into_iter()
            .map(|p| {
                let user_email = p.user_id.as_ref().and_then(|id| users_map.get(id).cloned());
                SuspiciousActivityAlert {
                    id: p.id,
                    org_id: p.org_id,
                    user_id: p.user_id,
                    user_email,
                    ip_address: p.ip_address,
                    failure_type: p.failure_type,
                    failure_count: p.failure_count,
                    is_suspicious: p.is_suspicious,
                    first_seen_at: p.first_seen_at.to_string(),
                    last_seen_at: p.last_seen_at.to_string(),
                    details: p.details,
                }
            })
            .collect())
    }

    /// Check if activity from user/IP is suspicious
    #[allow(dead_code)]
    pub async fn is_suspicious(
        &self,
        user_id: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<bool> {
        let mut query = mfa_failure_patterns::Entity::find()
            .filter(mfa_failure_patterns::Column::IsSuspicious.eq(true));

        if let Some(uid) = user_id {
            query = query.filter(mfa_failure_patterns::Column::UserId.eq(uid));
        }
        if let Some(ip) = ip_address {
            query = query.filter(mfa_failure_patterns::Column::IpAddress.eq(ip));
        }

        let pattern = query.one(&self.db).await?;
        Ok(pattern.is_some())
    }

    // ========================================
    // MFA Daily Metrics Generation
    // ========================================

    /// Generate daily metrics for the specified date and organization
    /// If org_id is None, generates platform-wide metrics
    pub async fn generate_daily_metrics(
        &self,
        org_id: Option<&str>,
        date: chrono::NaiveDate,
    ) -> Result<mfa_daily_metrics::Model> {
        let date_str = date.format("%Y-%m-%d").to_string();
        let now = Utc::now().naive_utc();

        // Get time range for the day
        let start_of_day = date.and_hms_opt(0, 0, 0).unwrap();
        let end_of_day = date.and_hms_opt(23, 59, 59).unwrap();

        // Build query for audit events
        let mut audit_query = mfa_audit_log::Entity::find()
            .filter(mfa_audit_log::Column::CreatedAt.between(start_of_day, end_of_day));

        if let Some(oid) = org_id {
            audit_query = audit_query.filter(mfa_audit_log::Column::OrgId.eq(oid));
        }

        let events = audit_query.all(&self.db).await?;

        // Count different event types
        let mut new_mfa_setups = 0;
        let mut mfa_disabled = 0;
        let mut totp_verifications_total = 0;
        let mut totp_verifications_success = 0;
        let mut totp_verifications_failed = 0;
        let mut backup_codes_generated = 0;
        let mut backup_codes_used = 0;

        for event in events {
            match event.event_type.as_str() {
                "mfa_enabled" | "mfa_setup_completed" => new_mfa_setups += 1,
                "mfa_disabled" | "mfa_force_disabled_by_admin" => mfa_disabled += 1,
                "mfa_verify_success" => {
                    totp_verifications_total += 1;
                    totp_verifications_success += 1;
                }
                "mfa_verify_failed" => {
                    totp_verifications_total += 1;
                    totp_verifications_failed += 1;
                }
                "backup_codes_generated" => backup_codes_generated += 1,
                "backup_code_used" => backup_codes_used += 1,
                _ => {}
            }
        }

        // Count total users and MFA-enabled users
        // Users belong to orgs via memberships, not directly
        let total_users = if let Some(oid) = org_id {
            use crate::entities::memberships;
            memberships::Entity::find()
                .filter(memberships::Column::OrgId.eq(oid))
                .count(&self.db)
                .await? as i32
        } else {
            users::Entity::find().count(&self.db).await? as i32
        };

        // Count users with MFA enabled (have a totp secret that is enabled)
        // For org-specific, we'd need to join totp_secrets -> users -> memberships
        // For simplicity, we'll use the event-based count when org-specific
        let mfa_enabled_users = if org_id.is_some() {
            // For org-specific, use event-based estimation
            // In a real system, you'd do a proper join query
            new_mfa_setups.max(0)
        } else {
            // Platform-wide: count all enabled TOTP secrets
            user_totp_secrets::Entity::find()
                .filter(user_totp_secrets::Column::Enabled.eq(true))
                .count(&self.db)
                .await? as i32
        };

        // Upsert the daily metrics
        let metrics_id = Uuid::new_v4().to_string();

        let new_metrics = mfa_daily_metrics::ActiveModel {
            id: Set(metrics_id),
            org_id: Set(org_id.map(|s| s.to_string())),
            date: Set(date_str.clone()),
            total_users: Set(total_users),
            mfa_enabled_users: Set(mfa_enabled_users),
            new_mfa_setups: Set(new_mfa_setups),
            mfa_disabled: Set(mfa_disabled),
            totp_verifications_total: Set(totp_verifications_total),
            totp_verifications_success: Set(totp_verifications_success),
            totp_verifications_failed: Set(totp_verifications_failed),
            backup_codes_generated: Set(backup_codes_generated),
            backup_codes_used: Set(backup_codes_used),
            created_at: Set(now),
            updated_at: Set(now),
        };

        // Use insert with on_conflict for upsert
        mfa_daily_metrics::Entity::insert(new_metrics.clone())
            .on_conflict(
                OnConflict::columns([
                    mfa_daily_metrics::Column::OrgId,
                    mfa_daily_metrics::Column::Date,
                ])
                .update_columns([
                    mfa_daily_metrics::Column::TotalUsers,
                    mfa_daily_metrics::Column::MfaEnabledUsers,
                    mfa_daily_metrics::Column::NewMfaSetups,
                    mfa_daily_metrics::Column::MfaDisabled,
                    mfa_daily_metrics::Column::TotpVerificationsTotal,
                    mfa_daily_metrics::Column::TotpVerificationsSuccess,
                    mfa_daily_metrics::Column::TotpVerificationsFailed,
                    mfa_daily_metrics::Column::BackupCodesGenerated,
                    mfa_daily_metrics::Column::BackupCodesUsed,
                    mfa_daily_metrics::Column::UpdatedAt,
                ])
                .to_owned(),
            )
            .exec(&self.db)
            .await?;

        // Fetch the inserted/updated record
        let result = mfa_daily_metrics::Entity::find()
            .filter(mfa_daily_metrics::Column::Date.eq(&date_str))
            .filter(if let Some(oid) = org_id {
                mfa_daily_metrics::Column::OrgId.eq(oid)
            } else {
                mfa_daily_metrics::Column::OrgId.is_null()
            })
            .one(&self.db)
            .await?
            .expect("Just inserted metrics should exist");

        Ok(result)
    }

    /// Get MFA metrics summary for an organization (or platform-wide if org_id is None)
    pub async fn get_mfa_metrics(
        &self,
        org_id: Option<&str>,
        days: Option<i64>,
    ) -> Result<Vec<MfaMetricsSummary>> {
        let days_val = days.unwrap_or(30);
        let cutoff = Utc::now().naive_utc() - Duration::days(days_val);
        let cutoff_date = cutoff.format("%Y-%m-%d").to_string();

        let mut query = mfa_daily_metrics::Entity::find()
            .filter(mfa_daily_metrics::Column::Date.gte(&cutoff_date));

        if let Some(oid) = org_id {
            query = query.filter(mfa_daily_metrics::Column::OrgId.eq(oid));
        } else {
            query = query.filter(mfa_daily_metrics::Column::OrgId.is_null());
        }

        let metrics = query
            .order_by_desc(mfa_daily_metrics::Column::Date)
            .all(&self.db)
            .await?;

        Ok(metrics
            .into_iter()
            .map(|m| MfaMetricsSummary {
                org_id: m.org_id,
                date: m.date,
                total_users: m.total_users,
                mfa_enabled_users: m.mfa_enabled_users,
                new_mfa_setups: m.new_mfa_setups,
                mfa_disabled: m.mfa_disabled,
                totp_verifications_total: m.totp_verifications_total,
                totp_verifications_success: m.totp_verifications_success,
                totp_verifications_failed: m.totp_verifications_failed,
                backup_codes_generated: m.backup_codes_generated,
                backup_codes_used: m.backup_codes_used,
            })
            .collect())
    }

    /// Generate metrics for all organizations and platform-wide for a given date
    #[allow(dead_code)]
    pub async fn generate_all_daily_metrics(
        &self,
        date: chrono::NaiveDate,
    ) -> Result<Vec<mfa_daily_metrics::Model>> {
        use crate::entities::organizations;

        // Get all organizations
        let orgs = organizations::Entity::find().all(&self.db).await?;

        let mut results = Vec::new();

        // Generate metrics for each org
        for org in orgs {
            match self.generate_daily_metrics(Some(&org.id), date).await {
                Ok(m) => results.push(m),
                Err(e) => tracing::warn!("Failed to generate metrics for org {}: {}", org.id, e),
            }
        }

        // Generate platform-wide metrics (org_id = None)
        match self.generate_daily_metrics(None, date).await {
            Ok(m) => results.push(m),
            Err(e) => tracing::warn!("Failed to generate platform-wide metrics: {}", e),
        }

        Ok(results)
    }
}
