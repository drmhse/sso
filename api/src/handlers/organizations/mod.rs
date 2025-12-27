mod billing;
mod billing_credentials;
mod core;
mod members;
mod scim_tokens;
mod settings;
mod users;

// Re-export handlers
pub use billing::{create_billing_customer, create_portal_session, get_billing_info};
pub use billing_credentials::{
    delete_billing_credentials, get_billing_credentials, set_billing_credentials,
};
pub use core::{
    create_organization, delete_organization, get_organization, get_risk_settings,
    list_user_organizations, reset_risk_settings, update_organization, update_risk_settings,
};
pub use members::{list_members, remove_member, transfer_ownership, update_member_role};
pub use scim_tokens::{create_scim_token, delete_scim_token, list_scim_tokens, revoke_scim_token};
pub use settings::{
    delete_org_smtp, get_org_oauth_credentials, get_org_smtp, set_org_oauth_credentials,
    set_org_smtp,
};
pub use users::{get_end_user, list_end_users, revoke_end_user_sessions};

// Re-export helper functions that are used in other modules
pub use core::ensure_organization_active;

