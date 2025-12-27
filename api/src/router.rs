//! Application Router Module
//!
//! Organizes routes by domain for maintainability:
//! - Public routes (health, OIDC, SAML)
//! - Authentication routes (SSO, password, magic links)
//! - Protected routes (user, organizations, services)
//! - Platform admin routes
//! - Service API routes (API key auth)
//! - SCIM routes (provisioning)

use crate::config::Config;
use crate::handlers::analytics::*;
use crate::handlers::api_keys::*;
use crate::handlers::auth::*;
use crate::handlers::branding::*;
use crate::handlers::health::*;
use crate::handlers::identities::*;
use crate::handlers::invitations::*;
use crate::handlers::organization_audit::*;
use crate::handlers::organizations::*;
use crate::handlers::platform::*;
use crate::handlers::privacy::*;
use crate::handlers::provider_token::*;
use crate::handlers::saml::*;
use crate::handlers::scim::{
    create_group, create_user as create_scim_user, delete_group, delete_user as delete_scim_user,
    get_group, get_user as get_scim_user, list_groups, list_users as list_scim_users, patch_group,
    patch_user as patch_scim_user, update_group, update_user as update_scim_user,
};
use crate::handlers::service_api::{
    create_subscription, create_user as create_service_user,
    delete_subscription as delete_service_subscription, delete_user as delete_service_user,
    get_service_analytics, get_service_info, get_service_user, get_user_subscription,
    list_service_subscriptions, list_service_users, update_service_info, update_subscription,
    update_user as update_service_user,
};
use crate::handlers::services::*;
use crate::handlers::siem_configs::*;
use crate::handlers::subscription::{change_password, create_checkout, get_subscription};
use crate::handlers::user::{
    disable_mfa, get_device, get_mfa_status, get_user, list_devices, regenerate_backup_codes,
    revoke_all_devices, revoke_device, set_password, setup_mfa, trust_device, update_device_name,
    update_user, verify_and_enable_mfa,
};
use crate::handlers::webhooks::*;
use crate::middleware;
use crate::state::AppState;
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, patch, post},
    Router,
};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};

/// Build active organization routes (require org to be active, not suspended)
pub fn active_org_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // OAuth credentials management (BYOO)
        .route(
            "/api/organizations/:org_slug/oauth-credentials/:provider",
            post(set_org_oauth_credentials),
        )
        .route(
            "/api/organizations/:org_slug/oauth-credentials/:provider",
            get(get_org_oauth_credentials),
        )
        // End-user management routes
        .route("/api/organizations/:org_slug/users", get(list_end_users))
        .route(
            "/api/organizations/:org_slug/users/:user_id",
            get(get_end_user),
        )
        .route(
            "/api/organizations/:org_slug/users/:user_id/sessions",
            delete(revoke_end_user_sessions),
        )
        // Service management routes
        .route(
            "/api/organizations/:org_slug/services/:service_slug/plans",
            get(list_service_plans).post(create_plan),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/plans/:plan_id",
            patch(update_plan).delete(delete_plan),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/api-keys/:api_key_id",
            get(get_api_key).delete(delete_api_key),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug",
            get(get_service)
                .patch(update_service)
                .delete(delete_service),
        )
        .route(
            "/api/organizations/:org_slug/services",
            get(list_organization_services).post(create_service),
        )
        // SAML configuration routes
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml",
            post(configure_saml)
                .get(get_saml_config)
                .delete(delete_saml_config),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml/certificate",
            post(generate_saml_certificate).get(get_saml_certificate),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml/login",
            get(saml_idp_login),
        )
        // Stripe checkout route
        .route(
            "/api/organizations/:org_slug/services/:service_slug/checkout",
            post(create_checkout),
        )
        // Apply active organization check middleware
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_active_organization,
        ))
}

/// Build protected routes (require JWT authentication)
pub fn protected_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // User routes
        .route("/api/user", get(get_user))
        .route("/api/user", patch(update_user))
        .route("/api/user/change-password", post(change_password))
        .route("/api/user/set-password", post(set_password))
        .route("/api/subscription", get(get_subscription))
        .route("/api/provider-token/:provider", get(get_provider_token))
        // Identity linking routes
        .route("/api/user/identities", get(list_identities))
        .route("/api/user/identities/:provider/link", post(start_link))
        .route("/api/user/identities/:provider", delete(unlink_identity))
        // Device management routes
        .route("/api/user/devices", get(list_devices))
        .route("/api/user/devices/:device_id", get(get_device))
        .route("/api/user/devices/:device_id/revoke", post(revoke_device))
        .route("/api/user/devices/:device_id", patch(update_device_name))
        .route("/api/user/devices/:device_id/trust", post(trust_device))
        .route("/api/user/devices/revoke-all", post(revoke_all_devices))
        // Privacy routes (GDPR compliance)
        .route("/api/privacy/export/:user_id", get(export_user_data))
        .route("/api/privacy/forget/:user_id", delete(forget_user))
        // Passkey registration routes (require JWT)
        .route("/api/auth/passkeys/register/start", post(register_start))
        .route("/api/auth/passkeys/register/finish", post(register_finish))
        // Organization routes
        .route(
            "/api/organizations",
            get(list_user_organizations).post(create_organization),
        )
        .route(
            "/api/organizations/:org_slug",
            get(get_organization)
                .patch(update_organization)
                .delete(delete_organization),
        )
        .route("/api/organizations/:org_slug/members", get(list_members))
        .route(
            "/api/organizations/:org_slug/members/:user_id",
            patch(update_member_role),
        )
        .route(
            "/api/organizations/:org_slug/members/:user_id",
            post(remove_member),
        )
        .route(
            "/api/organizations/:org_slug/transfer-ownership",
            post(transfer_ownership),
        )
        // Billing routes
        .route(
            "/api/organizations/:org_slug/billing/portal",
            post(create_portal_session),
        )
        .route(
            "/api/organizations/:org_slug/billing/info",
            get(get_billing_info),
        )
        // BYOP billing credentials routes
        .route(
            "/api/organizations/:org_slug/billing-credentials/:provider",
            get(get_billing_credentials)
                .post(set_billing_credentials)
                .delete(delete_billing_credentials),
        )
        // Organization SMTP management routes
        .route(
            "/api/organizations/:org_slug/smtp",
            post(set_org_smtp).get(get_org_smtp).delete(delete_org_smtp),
        )
        // Organization risk settings routes
        .route(
            "/api/organizations/:org_slug/risk-settings",
            get(get_risk_settings).put(update_risk_settings),
        )
        .route(
            "/api/organizations/:org_slug/risk-settings/reset",
            post(reset_risk_settings),
        )
        // SCIM token management routes
        .route(
            "/api/organizations/:org_slug/scim-tokens",
            post(create_scim_token).get(list_scim_tokens),
        )
        .route(
            "/api/organizations/:org_slug/scim-tokens/:token_id/revoke",
            post(revoke_scim_token),
        )
        .route(
            "/api/organizations/:org_slug/scim-tokens/:token_id",
            delete(delete_scim_token),
        )
        // Invitation routes
        .route(
            "/api/organizations/:org_slug/invitations",
            post(create_invitation),
        )
        .route(
            "/api/organizations/:org_slug/invitations",
            get(list_invitations),
        )
        .route(
            "/api/organizations/:org_slug/invitations/:invitation_id",
            post(cancel_invitation),
        )
        .route("/api/invitations", get(list_user_invitations))
        // Organization audit log routes
        .route(
            "/api/organizations/:org_slug/audit-log",
            get(get_organization_audit_logs),
        )
        .route(
            "/api/organizations/:org_slug/audit-log/event-types",
            get(get_audit_event_types),
        )
        // Webhook management routes
        .route(
            "/api/organizations/:org_slug/webhooks",
            post(create_webhook).get(list_webhooks),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/:webhook_id",
            get(get_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/:webhook_id/deliveries",
            get(get_webhook_deliveries),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/event-types",
            get(get_webhook_event_types),
        )
        // SIEM configuration routes
        .route(
            "/api/organizations/:org_slug/siem-configs",
            post(create_siem_config).get(list_siem_configs),
        )
        .route(
            "/api/organizations/:org_slug/siem-configs/:config_id",
            get(get_siem_config)
                .put(update_siem_config)
                .delete(delete_siem_config),
        )
        .route(
            "/api/organizations/:org_slug/siem-configs/:config_id/test",
            post(test_siem_connection),
        )
        // Custom domain and branding routes
        .route(
            "/api/organizations/:org_slug/domain",
            post(set_custom_domain)
                .get(get_domain_configuration)
                .delete(delete_custom_domain),
        )
        .route(
            "/api/organizations/:org_slug/domain/verify",
            post(verify_custom_domain),
        )
        .route(
            "/api/organizations/:org_slug/branding",
            patch(update_branding).get(get_branding),
        )
        // Merge active org routes
        .merge(active_org_routes(state))
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build analytics routes (require JWT + org membership)
pub fn analytics_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/api/organizations/:org_slug/analytics/login-trends",
            get(get_login_trends),
        )
        .route(
            "/api/organizations/:org_slug/analytics/logins-by-service",
            get(get_logins_by_service),
        )
        .route(
            "/api/organizations/:org_slug/analytics/logins-by-provider",
            get(get_logins_by_provider),
        )
        .route(
            "/api/organizations/:org_slug/analytics/recent-logins",
            get(get_recent_logins),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build MFA routes with specialized rate limiting
pub fn mfa_routes(state: &AppState, config: &Config) -> Router<AppState> {
    Router::new()
        .route("/api/user/mfa/status", get(get_mfa_status))
        .route("/api/user/mfa/setup", post(setup_mfa))
        .route("/api/user/mfa/verify", post(verify_and_enable_mfa))
        .route("/api/user/mfa", delete(disable_mfa))
        .route(
            "/api/user/mfa/backup-codes/regenerate",
            post(regenerate_backup_codes),
        )
        .layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(if config.disable_rate_limiting { 1 } else { 300 })
                    .burst_size(if config.disable_rate_limiting {
                        10000
                    } else {
                        5
                    })
                    .key_extractor(SmartIpKeyExtractor)
                    .finish()
                    .expect("Failed to build MFA setup rate limiter"),
            )),
        })
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build MFA verification routes (stricter rate limiting)
pub fn mfa_verification_routes(config: &Config) -> Router<AppState> {
    Router::new()
        .route("/api/auth/mfa/verify", post(verify_mfa_login))
        .layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(if config.disable_rate_limiting {
                        1
                    } else {
                        1000
                    })
                    .burst_size(if config.disable_rate_limiting {
                        10000
                    } else {
                        3
                    })
                    .key_extractor(SmartIpKeyExtractor)
                    .finish()
                    .expect("Failed to build MFA rate limiter"),
            )),
        })
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
}

/// Build platform admin routes (require JWT + platform owner)
pub fn platform_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/api/platform/tiers", get(list_tiers))
        .route("/api/platform/organizations", get(list_organizations))
        .route(
            "/api/platform/organizations/:id/approve",
            post(approve_organization),
        )
        .route(
            "/api/platform/organizations/:id/reject",
            post(reject_organization),
        )
        .route(
            "/api/platform/organizations/:id/suspend",
            post(suspend_organization),
        )
        .route(
            "/api/platform/organizations/:id/activate",
            post(activate_organization),
        )
        .route(
            "/api/platform/organizations/:id/tier",
            patch(update_organization_tier),
        )
        .route(
            "/api/platform/organizations/:id/features",
            patch(update_organization_features),
        )
        .route(
            "/api/platform/organizations/:id",
            delete(delete_organization_platform),
        )
        .route("/api/platform/owners", post(promote_platform_owner))
        .route(
            "/api/platform/owners/:user_id",
            delete(demote_platform_owner),
        )
        .route("/api/platform/audit-log", get(get_audit_log))
        // Platform analytics routes
        .route(
            "/api/platform/analytics/overview",
            get(get_platform_overview),
        )
        .route(
            "/api/platform/analytics/organization-status",
            get(get_organization_status_breakdown),
        )
        .route(
            "/api/platform/analytics/growth-trends",
            get(get_growth_trends),
        )
        .route(
            "/api/platform/analytics/login-activity",
            get(get_login_activity),
        )
        .route(
            "/api/platform/analytics/top-organizations",
            get(get_top_organizations),
        )
        .route(
            "/api/platform/analytics/recent-organizations",
            get(get_recent_organizations),
        )
        // Platform MFA management routes
        .route(
            "/api/platform/users/:user_id/mfa/status",
            get(get_user_mfa_status),
        )
        .route(
            "/api/platform/users/:user_id/mfa",
            delete(force_disable_user_mfa),
        )
        .route("/api/platform/users/search", get(search_users))
        .route("/api/platform/impersonate", post(impersonate_user))
        .route("/api/platform/mfa/metrics", get(get_mfa_metrics))
        .route("/api/platform/mfa/suspicious", get(get_suspicious_activity))
        .route(
            "/api/platform/mfa/metrics/generate",
            get(generate_daily_metrics),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn(middleware::require_platform_owner))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build authentication routes with rate limiting
pub fn auth_routes(config: &Config) -> Router<AppState> {
    let rate_limiter_config = Box::leak(Box::new(
        GovernorConfigBuilder::default()
            .per_millisecond(if config.disable_rate_limiting {
                1
            } else {
                1000
            })
            .burst_size(if config.disable_rate_limiting {
                10000
            } else {
                20
            })
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build auth rate limiter"),
    ));

    Router::new()
        // SSO routes
        .route("/auth/:provider", get(auth_provider))
        .route("/auth/:provider/callback", get(auth_callback))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
        .route("/auth/revoke", post(revoke_token))
        // Admin authentication routes
        .route("/auth/admin/:provider", get(auth_admin_provider))
        .route("/auth/admin/:provider/callback", get(auth_admin_callback))
        // Password authentication routes
        .route("/api/auth/register", post(register))
        .route("/auth/verify-email", get(verify_email))
        .route("/api/auth/login", post(login))
        .route("/api/auth/forgot-password", post(forgot_password))
        .route("/api/auth/reset-password", post(reset_password))
        .route("/api/auth/resend-verification", post(resend_verification))
        // Home Realm Discovery
        .route("/api/auth/lookup-email", post(lookup_email))
        // Passkey authentication routes (public)
        .route(
            "/api/auth/passkeys/authenticate/start",
            post(authenticate_start),
        )
        .route(
            "/api/auth/passkeys/authenticate/finish",
            post(authenticate_finish),
        )
        // Magic link authentication routes
        .route("/api/auth/magic-link/request", post(request_magic_link))
        .route("/api/auth/magic-link/verify", get(verify_magic_link))
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .layer(GovernorLayer {
            config: rate_limiter_config,
        })
}

/// Build device flow routes with stricter rate limiting
pub fn device_routes(config: &Config) -> Router<AppState> {
    let rate_limiter_config = Box::leak(Box::new(
        GovernorConfigBuilder::default()
            .per_millisecond(if config.disable_rate_limiting {
                1
            } else {
                5000
            })
            .burst_size(if config.disable_rate_limiting {
                10000
            } else {
                10
            })
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build device rate limiter"),
    ));

    Router::new()
        .route("/auth/device/code", post(device_code))
        .route("/auth/device/verify", post(device_verify))
        .route("/auth/token", post(token_exchange))
        .layer(GovernorLayer {
            config: rate_limiter_config,
        })
}

/// Build service API routes (authenticated via API key)
pub fn service_api_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // User management
        .route(
            "/api/service/users",
            get(list_service_users).post(create_service_user),
        )
        .route(
            "/api/service/users/:user_id",
            get(get_service_user)
                .patch(update_service_user)
                .delete(delete_service_user),
        )
        // Subscription management
        .route(
            "/api/service/subscriptions",
            get(list_service_subscriptions).post(create_subscription),
        )
        .route(
            "/api/service/subscriptions/:user_id",
            get(get_user_subscription)
                .patch(update_subscription)
                .delete(delete_service_subscription),
        )
        // Analytics (read only)
        .route("/api/service/analytics", get(get_service_analytics))
        // Service info
        .route(
            "/api/service/info",
            get(get_service_info).patch(update_service_info),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.db.clone(),
            middleware::extract_api_key,
        ))
}

/// Build SCIM routes (authenticated via SCIM Bearer tokens)
pub fn scim_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // SCIM Users endpoints
        .route(
            "/scim/v2/Users",
            get(list_scim_users).post(create_scim_user),
        )
        .route(
            "/scim/v2/Users/:id",
            get(get_scim_user)
                .put(update_scim_user)
                .patch(patch_scim_user)
                .delete(delete_scim_user),
        )
        // SCIM Groups endpoints
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/:id",
            get(get_group)
                .put(update_group)
                .patch(patch_group)
                .delete(delete_group),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.db.clone(),
            middleware::scim_auth_middleware,
        ))
}

/// Build SAML IdP routes (public, no authentication required)
pub fn saml_routes() -> Router<AppState> {
    Router::new()
        // SAML IdP metadata endpoint
        .route("/saml/:org_slug/:service_slug/metadata", get(saml_metadata))
        // SAML SSO initiation endpoint
        .route(
            "/saml/:org_slug/:service_slug/sso",
            post(saml_sso).get(saml_sso),
        )
        // SAML Single Logout endpoint
        .route(
            "/saml/:org_slug/:service_slug/slo",
            post(saml_slo_post).get(saml_slo),
        )
        // SAML authentication page
        .route(
            "/saml/:org_slug/:service_slug/authenticate",
            get(saml_authenticate),
        )
}

/// Build public routes (no authentication required)
/// Note: OIDC discovery and JWKS endpoints should be added in main.rs
pub fn public_routes(config: &Config) -> Router<AppState> {
    Router::new()
        // Health check endpoints
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        // Public branding endpoint
        .route(
            "/api/organizations/:org_slug/branding/public",
            get(get_public_branding),
        )
        // Public invitation endpoints
        .route("/api/invitations/accept", post(accept_invitation))
        .route("/api/invitations/decline", post(decline_invitation))
        .route(
            "/invitations/accept/:token",
            get(accept_invitation_redirect),
        )
        .merge(auth_routes(config))
        .merge(device_routes(config))
        .merge(saml_routes())
}
