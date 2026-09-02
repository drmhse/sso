use crate::db::DB;
use crate::error::AppError;
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_AUDIT_LOGS_VIEW};
use crate::state::AppState;
use crate::store::{
    login_events::{
        LoginEventStore, LoginTrendPoint, LoginsByProvider, LoginsByService, RecentLogin,
    },
    organizations::OrganizationStore,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use sea_orm::DatabaseConnection;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
}

/// GET /api/organizations/:org_slug/analytics/login-trends
pub async fn get_login_trends(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginTrendPoint>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    let trends = LoginEventStore::get_login_trends(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(trends))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-service
pub async fn get_logins_by_service(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginsByService>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    // Query logins using store
    let logins = LoginEventStore::get_logins_by_service(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(logins))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-provider
pub async fn get_logins_by_provider(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginsByProvider>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    // Query logins using store
    let logins = LoginEventStore::get_logins_by_provider(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(logins))
}

/// GET /api/organizations/:org_slug/analytics/recent-logins
pub async fn get_recent_logins(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<RecentLogin>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    let limit = query.limit.unwrap_or(10).clamp(1, 100);

    // Query recent logins using store
    let logins =
        LoginEventStore::get_recent_logins(DB::Conn(&state.db), &organization.id, limit).await?;

    Ok(Json(logins))
}

/// Resolve the current organization and authorize access to its sensitive
/// login analytics. This deliberately follows the same capability boundary as
/// tenant audit-log reads: ordinary membership alone does not expose user IDs,
/// and a suspended parent or revoked custom role takes effect immediately.
async fn require_org_analytics_viewer(
    pool: &DatabaseConnection,
    user_id: &str,
    org_slug: &str,
) -> std::result::Result<crate::entities::organizations::Model, AppError> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(pool), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(pool, &organization.id).await?;

    if !PermissionService::check(
        DB::Conn(pool),
        &organization.id,
        user_id,
        CAP_AUDIT_LOGS_VIEW,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view organization analytics".to_string(),
        ));
    }

    Ok(organization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::login_events;
    use crate::store::{
        memberships::MembershipStore,
        organization_roles::OrganizationRoleStore,
        services::ServiceStore,
        users::{UserCreationOptions, UserStore},
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, Set};

    async fn create_user(db: &DatabaseConnection, email: &str) -> crate::entities::users::Model {
        UserStore::find_or_create_with_options(
            DB::Conn(db),
            email,
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0
    }

    #[tokio::test]
    async fn tenant_analytics_requires_live_scoped_capability_and_excludes_other_scopes() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = create_user(&db, "analytics-owner@example.com").await;
        let admin = create_user(&db, "analytics-admin@example.com").await;
        let member = create_user(&db, "analytics-member@example.com").await;
        let viewer = create_user(&db, "analytics-viewer@example.com").await;
        let outsider = create_user(&db, "analytics-outsider@example.com").await;
        let other_owner = create_user(&db, "analytics-other-owner@example.com").await;

        let org = OrganizationStore::create(
            DB::Conn(&db),
            "analytics-org",
            "Analytics Org",
            &owner.id,
            None,
        )
        .await
        .expect("create organization");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate organization");
        let other_org = OrganizationStore::create(
            DB::Conn(&db),
            "analytics-other-org",
            "Other Analytics Org",
            &other_owner.id,
            None,
        )
        .await
        .expect("create other organization");
        OrganizationStore::update_status(DB::Conn(&db), &other_org.id, "active")
            .await
            .expect("activate other organization");

        MembershipStore::create(DB::Conn(&db), &org.id, &owner.id, "owner")
            .await
            .expect("create owner membership");
        MembershipStore::create(DB::Conn(&db), &org.id, &admin.id, "admin")
            .await
            .expect("create admin membership");
        MembershipStore::create(DB::Conn(&db), &org.id, &member.id, "member")
            .await
            .expect("create member membership");
        OrganizationRoleStore::create(
            DB::Conn(&db),
            "analytics-viewer-role",
            &org.id,
            "analytics-viewer",
            "Analytics viewer",
            None,
            serde_json::json!([CAP_AUDIT_LOGS_VIEW]),
        )
        .await
        .expect("create custom analytics role");
        MembershipStore::create(DB::Conn(&db), &org.id, &viewer.id, "analytics-viewer")
            .await
            .expect("create custom viewer membership");
        MembershipStore::create(DB::Conn(&db), &other_org.id, &other_owner.id, "owner")
            .await
            .expect("create other owner membership");

        for allowed in [&owner, &admin, &viewer] {
            assert_eq!(
                require_org_analytics_viewer(&db, &allowed.id, &org.slug)
                    .await
                    .expect("authorized analytics viewer")
                    .id,
                org.id
            );
        }
        for denied in [&member, &outsider, &other_owner] {
            assert!(matches!(
                require_org_analytics_viewer(&db, &denied.id, &org.slug).await,
                Err(AppError::Forbidden(_))
            ));
        }
        assert!(matches!(
            require_org_analytics_viewer(&db, &owner.id, "missing-analytics-org").await,
            Err(AppError::NotFound(_))
        ));

        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend organization");
        assert!(matches!(
            require_org_analytics_viewer(&db, &owner.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("reactivate organization");
        OrganizationRoleStore::update(
            DB::Conn(&db),
            "analytics-viewer-role",
            None,
            None,
            Some(serde_json::json!([])),
        )
        .await
        .expect("revoke custom analytics capability");
        assert!(matches!(
            require_org_analytics_viewer(&db, &viewer.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));

        let service = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "primary",
            "Primary",
            "web",
            "analytics-primary-client",
        )
        .await
        .expect("create tenant service");
        let other_service = ServiceStore::create(
            DB::Conn(&db),
            &other_org.id,
            "other",
            "Other",
            "web",
            "analytics-other-client",
        )
        .await
        .expect("create other tenant service");
        let now = Utc::now().naive_utc();
        for (id, user_id, service_id, org_id, provider) in [
            (
                "analytics-event-a1",
                owner.id.as_str(),
                Some(service.id.as_str()),
                None,
                "password",
            ),
            (
                "analytics-event-a2",
                admin.id.as_str(),
                Some(service.id.as_str()),
                None,
                "github",
            ),
            (
                "analytics-event-b",
                other_owner.id.as_str(),
                Some(other_service.id.as_str()),
                None,
                "microsoft",
            ),
            (
                "analytics-event-global",
                outsider.id.as_str(),
                None,
                Some(org.id.as_str()),
                "magic",
            ),
            (
                "analytics-event-mismatch",
                outsider.id.as_str(),
                Some(other_service.id.as_str()),
                Some(org.id.as_str()),
                "passkey",
            ),
        ] {
            login_events::ActiveModel {
                id: Set(id.to_string()),
                user_id: Set(user_id.to_string()),
                service_id: Set(service_id.map(str::to_string)),
                org_id: Set(org_id.map(str::to_string)),
                provider: Set(provider.to_string()),
                created_at: Set(now),
                ..Default::default()
            }
            .insert(&db)
            .await
            .expect("insert login event fixture");
        }

        let recent = LoginEventStore::get_recent_logins(DB::Conn(&db), &org.id, 100)
            .await
            .expect("load tenant recent logins");
        assert_eq!(recent.len(), 3);
        assert!(recent.iter().any(|event| event.service_id.is_none()));
        assert!(recent
            .iter()
            .filter_map(|event| event.service_id.as_deref())
            .all(|service_id| service_id == service.id));
        assert_eq!(
            recent
                .iter()
                .filter(|event| event.user_id == outsider.id)
                .count(),
            1
        );
        assert!(recent.iter().all(|event| event.user_id != other_owner.id));

        // The defensive store clamp prevents signed-to-unsigned expansion even
        // for non-HTTP callers.
        let clamped = LoginEventStore::get_recent_logins(DB::Conn(&db), &org.id, -1)
            .await
            .expect("load clamped recent logins");
        assert_eq!(clamped.len(), 1);

        let providers = LoginEventStore::get_logins_by_provider(
            DB::Conn(&db),
            &org.id,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(1),
        )
        .await
        .expect("load tenant provider aggregation");
        assert_eq!(providers.len(), 3);
        assert!(providers.iter().all(|row| row.provider != "microsoft"));
        assert!(providers.iter().all(|row| row.provider != "passkey"));
        assert_eq!(providers.iter().map(|row| row.count).sum::<i64>(), 3);
    }
}
