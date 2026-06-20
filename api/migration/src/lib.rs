pub use sea_orm_migration::prelude::*;

mod m20240101_000001_initial_schema;
mod m20241213_000001_add_worker_id_to_system_jobs;
mod m20251218_000001_add_upstream_connection_id_to_oauth_states;
mod m20251225_000001_add_feature_overrides;
mod m20251225_000002_billing_generalization;
mod m20251225_000003_organization_billing_credentials;
mod m20251230_000001_add_org_id_to_login_events;
mod m20251230_000002_create_organization_roles;
mod m20260103_000001_add_org_id_to_users;
mod m20260104_000001_scope_existing_users;
mod m20260110_000001_add_plan_description_and_default;
mod m20260509_000001_linked_provider_grants;
mod m20260510_000001_oauth_state_provider_token_metadata;
mod m20260529_000001_oauth_state_client_state;
mod m20260612_000001_add_login_policy_to_verified_domains;
mod m20260612_000002_add_resource_uris_to_services;
mod m20260612_000003_add_resource_to_oauth_states_and_sessions;
mod m20260620_000001_create_oauth_authorization_grants;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000001_initial_schema::Migration),
            Box::new(m20241213_000001_add_worker_id_to_system_jobs::Migration),
            Box::new(m20251218_000001_add_upstream_connection_id_to_oauth_states::Migration),
            Box::new(m20251225_000001_add_feature_overrides::Migration),
            Box::new(m20251225_000002_billing_generalization::Migration),
            Box::new(m20251225_000003_organization_billing_credentials::Migration),
            Box::new(m20251230_000001_add_org_id_to_login_events::Migration),
            Box::new(m20251230_000002_create_organization_roles::Migration),
            Box::new(m20260103_000001_add_org_id_to_users::Migration),
            Box::new(m20260104_000001_scope_existing_users::Migration),
            Box::new(m20260110_000001_add_plan_description_and_default::Migration),
            Box::new(m20260509_000001_linked_provider_grants::Migration),
            Box::new(m20260510_000001_oauth_state_provider_token_metadata::Migration),
            Box::new(m20260529_000001_oauth_state_client_state::Migration),
            Box::new(m20260612_000001_add_login_policy_to_verified_domains::Migration),
            Box::new(m20260612_000002_add_resource_uris_to_services::Migration),
            Box::new(m20260612_000003_add_resource_to_oauth_states_and_sessions::Migration),
            Box::new(m20260620_000001_create_oauth_authorization_grants::Migration),
        ]
    }
}
