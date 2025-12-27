pub use sea_orm_migration::prelude::*;

mod m20240101_000001_initial_schema;
mod m20241213_000001_add_worker_id_to_system_jobs;
mod m20251218_000001_add_upstream_connection_id_to_oauth_states;
mod m20251225_000001_add_feature_overrides;
mod m20251225_000002_billing_generalization;
mod m20251225_000003_organization_billing_credentials;

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
        ]
    }
}

