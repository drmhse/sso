mod billing;
mod billing_credentials;
mod core;
mod domain_routing;
mod members;
mod scim_tokens;
mod settings;
mod upstream_providers;
mod users;

// Re-export handlers
pub use billing::{create_billing_customer, create_portal_session, get_billing_info};
pub use billing_credentials::{
    delete_billing_credentials, get_billing_credentials, set_billing_credentials,
};
pub use core::{
    create_organization, delete_organization, get_organization, get_risk_settings,
    list_user_organizations, reset_risk_settings, select_organization, update_organization,
    update_risk_settings,
};
pub use domain_routing::{
    create_domain_route, delete_domain_route, list_domain_routes, update_domain_route,
    verify_domain_route,
};
pub use members::{
    list_member_service_access, list_members, remove_member, transfer_ownership,
    update_member_role, update_member_service_access,
};
pub mod risk;
pub use scim_tokens::{create_scim_token, delete_scim_token, list_scim_tokens, revoke_scim_token};
pub use settings::{
    delete_org_smtp, get_org_oauth_credentials, get_org_smtp, set_org_oauth_credentials,
    set_org_smtp,
};
pub use upstream_providers::{
    create_upstream_provider, delete_upstream_provider, get_upstream_provider,
    list_upstream_providers, update_upstream_provider,
};
pub use users::{get_end_user, list_end_users, revoke_end_user_sessions};

// Re-export helper functions that are used in other modules
pub use crate::store::organizations::ensure_organization_active;

pub mod roles;
