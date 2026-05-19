//! Store layer - comprehensive database access functions.
//! Many functions are intentionally kept for API completeness,
//! even if not currently used by handlers.
#![allow(dead_code)]

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, ExecResult, QueryResult,
    Statement,
};
use std::future::Future;
use std::pin::Pin;

pub mod api_keys;
pub mod connected_accounts;
pub mod device_codes;
pub mod distributed_locks;
pub mod email_verification;
pub mod identities;
pub mod invitations;
pub mod login_events;
pub mod magic_links;
pub mod memberships;
pub mod oauth_states;
pub mod organization_billing_credentials;
pub mod organization_oauth_credentials;
pub mod organization_tiers;
pub mod organizations;
pub mod password_reset;
pub mod permissions;
pub mod plans;
pub mod platform_audit_log;
pub mod provider_token_requests;
pub mod risk_rules;
pub mod saml_signing_keys;
pub mod saml_states;
pub mod scim_tokens;
pub mod service_provider_grants;
pub mod services;
pub mod sessions;
pub mod siem_configs;
pub mod subscriptions;
pub mod system_jobs;
pub mod token_refresh_locks;
pub mod totp;
pub mod upstream_providers;
pub mod user_devices;
pub mod user_passkeys;
pub mod users;
pub mod verified_domains;
pub mod webauthn_challenges;
pub mod webhook_deliveries;
pub mod webhooks;

/// A helper enum that allows store functions to work with either a direct database connection
/// or a transaction. This enables the same store methods to be used in both contexts.
#[derive(Clone)]
pub enum DB<'a> {
    Conn(&'a DatabaseConnection),
    Tx(&'a DatabaseTransaction),
}

impl<'a> ConnectionTrait for DB<'a> {
    fn get_database_backend(&self) -> DbBackend {
        match self {
            DB::Conn(c) => c.get_database_backend(),
            DB::Tx(t) => t.get_database_backend(),
        }
    }

    fn execute<'life0, 'async_trait>(
        &'life0 self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, sea_orm::DbErr>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.execute(stmt),
            DB::Tx(t) => t.execute(stmt),
        }
    }

    fn execute_unprepared<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sql: &'life1 str,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, sea_orm::DbErr>> + Send + 'async_trait>>
    where
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.execute_unprepared(sql),
            DB::Tx(t) => t.execute_unprepared(sql),
        }
    }

    fn query_one<'life0, 'async_trait>(
        &'life0 self,
        stmt: Statement,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<QueryResult>, sea_orm::DbErr>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.query_one(stmt),
            DB::Tx(t) => t.query_one(stmt),
        }
    }

    fn query_all<'life0, 'async_trait>(
        &'life0 self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<QueryResult>, sea_orm::DbErr>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.query_all(stmt),
            DB::Tx(t) => t.query_all(stmt),
        }
    }
}
pub mod organization_roles;
