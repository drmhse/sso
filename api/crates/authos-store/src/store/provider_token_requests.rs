use crate::audit::actor::AuditHandle;
use crate::db::DB;
use crate::entities::prelude::ProviderTokenRequests;
use crate::entities::{organization_audit_log, provider_token_requests, service_provider_grants};
use crate::error::{AppError, Result};
use crate::store::{
    identities::IdentityStore, organizations::OrganizationStore,
    service_provider_grants::ServiceProviderGrantStore, services::ServiceStore,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct ProviderTokenRequestStore;

impl ProviderTokenRequestStore {
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        provider: &str,
        connected_account_id: Option<&str>,
        requested_scopes: &[String],
        redirect_uri: &str,
        client_state: Option<&str>,
    ) -> Result<provider_token_requests::Model> {
        let requested_scopes_json = serde_json::to_string(requested_scopes)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let now = chrono::Utc::now();
        let active = provider_token_requests::ActiveModel {
            state: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.to_string()),
            provider: Set(provider.to_string()),
            connected_account_id: Set(connected_account_id.map(str::to_string)),
            requested_scopes: Set(requested_scopes_json),
            redirect_uri: Set(redirect_uri.to_string()),
            client_state: Set(client_state.map(str::to_string)),
            status: Set("pending".to_string()),
            created_at: Set(now.naive_utc()),
            expires_at: Set((now + chrono::Duration::minutes(15)).naive_utc()),
            completed_at: Set(None),
        };
        Ok(active.insert(&db).await?)
    }

    pub async fn find_active_for_user(
        db: DB<'_>,
        state: &str,
        user_id: &str,
    ) -> Result<Option<provider_token_requests::Model>> {
        Ok(ProviderTokenRequests::find()
            .filter(provider_token_requests::Column::State.eq(state))
            .filter(provider_token_requests::Column::UserId.eq(user_id))
            .filter(provider_token_requests::Column::Status.eq("pending"))
            .filter(provider_token_requests::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
            .one(&db)
            .await?)
    }

    pub async fn find_active(
        db: DB<'_>,
        state: &str,
    ) -> Result<Option<provider_token_requests::Model>> {
        Ok(ProviderTokenRequests::find()
            .filter(provider_token_requests::Column::State.eq(state))
            .filter(provider_token_requests::Column::Status.eq("pending"))
            .filter(provider_token_requests::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
            .one(&db)
            .await?)
    }

    pub async fn complete(db: DB<'_>, state: &str, user_id: &str) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        let result = ProviderTokenRequests::update_many()
            .filter(provider_token_requests::Column::State.eq(state))
            .filter(provider_token_requests::Column::UserId.eq(user_id))
            .filter(provider_token_requests::Column::Status.eq("pending"))
            .filter(provider_token_requests::Column::ExpiresAt.gt(now))
            .col_expr(
                provider_token_requests::Column::Status,
                sea_orm::sea_query::Expr::value("completed"),
            )
            .col_expr(
                provider_token_requests::Column::CompletedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .exec(&db)
            .await?;
        if result.rows_affected != 1 {
            return Err(AppError::NotFound(
                "Provider token request not found".to_string(),
            ));
        }
        Ok(())
    }

    /// Atomically claim a one-time provider request, write its grant, and
    /// durably enqueue every success audit required by the caller.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_with_grant_and_audits_in_transaction(
        db: DB<'_>,
        audit_actor: &AuditHandle,
        state: &str,
        user_id: &str,
        service_id: &str,
        connected_account_id: &str,
        provider: &str,
        scopes: &[String],
        audit_events: Vec<organization_audit_log::ActiveModel>,
    ) -> Result<service_provider_grants::Model> {
        let DB::Tx(transaction) = db else {
            return Err(AppError::InternalServerError(
                "Provider request completion requires a database transaction".to_string(),
            ));
        };
        let db = DB::Tx(transaction);
        let request = Self::find_active_for_user(db.clone(), state, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
        let requested_scopes: Vec<String> = serde_json::from_str(&request.requested_scopes)
            .map_err(|_| {
                AppError::InternalServerError(
                    "Provider token request contains invalid scopes".to_string(),
                )
            })?;
        let requested_scopes = crate::utils::scopes::normalize_scope_list(requested_scopes);
        let completion_scopes = crate::utils::scopes::normalize_scope_list(scopes);
        if request.service_id != service_id
            || request.provider != provider
            || request
                .connected_account_id
                .as_deref()
                .is_some_and(|expected| expected != connected_account_id)
            || requested_scopes != completion_scopes
        {
            return Err(AppError::BadRequest(
                "Provider token request context does not match completion".to_string(),
            ));
        }

        let service = ServiceStore::find_by_id(db.clone(), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
        let organization = OrganizationStore::find_by_id(db.clone(), &service.org_id)
            .await?
            .filter(|organization| organization.status == "active")
            .ok_or_else(|| {
                AppError::Forbidden("User has not authenticated with this service".to_string())
            })?;
        if !IdentityStore::user_has_authenticated_with_org_service(
            db.clone(),
            user_id,
            &organization.id,
            service_id,
        )
        .await?
        {
            return Err(AppError::Forbidden(
                "User has not authenticated with this service".to_string(),
            ));
        }

        Self::complete(db.clone(), state, user_id).await?;
        let grant = ServiceProviderGrantStore::upsert(
            db.clone(),
            user_id,
            service_id,
            connected_account_id,
            provider,
            scopes,
        )
        .await?;
        for event in audit_events {
            audit_actor.log_org_with_db(db.clone(), event).await?;
        }
        Ok(grant)
    }

    pub async fn cancel_pending_for_user_service(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<u64> {
        let result = ProviderTokenRequests::update_many()
            .col_expr(
                provider_token_requests::Column::Status,
                sea_orm::sea_query::Expr::value("canceled"),
            )
            .filter(provider_token_requests::Column::UserId.eq(user_id))
            .filter(provider_token_requests::Column::ServiceId.eq(service_id))
            .filter(provider_token_requests::Column::Status.eq("pending"))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::actor::AuditHandle;
    #[cfg(feature = "db_sqlite")]
    use crate::db::transaction::with_retrying_transaction;
    #[cfg(feature = "db_sqlite")]
    use crate::entities::{audit_outbox, organization_audit_log, service_provider_grants};
    #[cfg(feature = "db_sqlite")]
    use crate::services::audit_builder::OrgAuditBuilder;
    #[cfg(feature = "db_sqlite")]
    use crate::store::{
        connected_accounts::ConnectedAccountStore, identities::IdentityStore,
        service_provider_grants::ServiceProviderGrantStore,
    };
    use crate::store::{
        organizations::OrganizationStore, services::ServiceStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    #[cfg(feature = "db_sqlite")]
    use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

    #[tokio::test]
    async fn provider_token_request_completion_is_user_bound_and_one_time() {
        let path = std::env::temp_dir().join(format!(
            "authos-provider-request-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "request-owner@example.test", None, false)
            .await
            .expect("create owner");
        let other = UserStore::create(DB::Conn(&db), "request-other@example.test", None, false)
            .await
            .expect("create other user");
        let org =
            OrganizationStore::create(DB::Conn(&db), "request-org", "Request Org", &owner.id, None)
                .await
                .expect("create org");
        let service = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "request-service",
            "Request Service",
            "web",
            "request-client",
        )
        .await
        .expect("create service");
        let request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &owner.id,
            &service.id,
            "github",
            None,
            &["read:user".to_string()],
            "https://client.example/callback",
            Some("client-state"),
        )
        .await
        .expect("create request");

        assert!(matches!(
            ProviderTokenRequestStore::complete(DB::Conn(&db), &request.state, &other.id).await,
            Err(AppError::NotFound(_))
        ));
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &request.state,
            &owner.id,
        )
        .await
        .expect("load preserved request")
        .is_some());

        let first = ProviderTokenRequestStore::complete(DB::Conn(&db), &request.state, &owner.id);
        let second = ProviderTokenRequestStore::complete(DB::Conn(&db), &request.state, &owner.id);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &request.state,
            &owner.id,
        )
        .await
        .expect("request consumed")
        .is_none());

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "db_sqlite")]
    #[tokio::test]
    async fn transactional_completion_rolls_back_failures_and_has_one_concurrent_winner() {
        let path = std::env::temp_dir().join(format!(
            "authos-provider-request-atomic-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "atomic-owner@example.test", None, false)
            .await
            .expect("create owner");
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "atomic-request-org",
            "Atomic Request Org",
            &owner.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let user =
            UserStore::create_with_org_id(DB::Conn(&db), "atomic-user@example.test", None, &org.id)
                .await
                .expect("create tenant user");
        let service = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "atomic-request-service",
            "Atomic Request Service",
            "web",
            "atomic-request-client",
        )
        .await
        .expect("create service");
        let identity = IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "password",
            &user.id,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service.id),
        )
        .await
        .expect("create exact service identity");
        let account = ConnectedAccountStore::upsert_from_oauth_details(
            DB::Conn(&db),
            None,
            &user.id,
            "github",
            "atomic-provider-user",
            Some(&user.email),
            None,
            "access-token",
            None,
            None,
            &["read:user".to_string()],
        )
        .await
        .expect("create connected account");
        let audit_actor = AuditHandle::new(db.clone());
        let scopes = vec!["read:user".to_string()];

        let mismatch_request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &user.id,
            &service.id,
            "github",
            Some(&account.id),
            &scopes,
            "https://client.example/callback",
            None,
        )
        .await
        .expect("create context-mismatch request");
        let mismatch_event =
            OrgAuditBuilder::new(&org.id, Some(&user.id), "provider_token_request.completed")
                .target("provider_token_request", &mismatch_request.state)
                .build();
        let mismatch = with_retrying_transaction(
            &db,
            &db,
            "provider_request_context_mismatch",
            |transaction| {
                let audit_actor = audit_actor.clone();
                let request = mismatch_request.clone();
                let user_id = user.id.clone();
                let service_id = service.id.clone();
                let account_id = account.id.clone();
                let scopes = scopes.clone();
                let event = mismatch_event.clone();
                Box::pin(async move {
                    ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                        transaction,
                        &audit_actor,
                        &request.state,
                        &user_id,
                        &service_id,
                        &account_id,
                        "google",
                        &scopes,
                        vec![event],
                    )
                    .await
                })
            },
        )
        .await;
        assert!(matches!(mismatch, Err(AppError::BadRequest(_))));
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &mismatch_request.state,
            &user.id,
        )
        .await
        .expect("read context-mismatch request")
        .is_some());
        assert!(ServiceProviderGrantStore::find_active(
            DB::Conn(&db),
            &user.id,
            &service.id,
            &account.id,
        )
        .await
        .expect("read denied context-mismatch grant")
        .is_none());

        let grant_failure_request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &user.id,
            &service.id,
            "github",
            None,
            &scopes,
            "https://client.example/callback",
            None,
        )
        .await
        .expect("create grant-failure request");
        let grant_failure_event =
            OrgAuditBuilder::new(&org.id, Some(&user.id), "provider_token_request.completed")
                .target("provider_token_request", &grant_failure_request.state)
                .build();
        let grant_failure = with_retrying_transaction(
            &db,
            &db,
            "provider_request_injected_grant_failure",
            |transaction| {
                let audit_actor = audit_actor.clone();
                let request = grant_failure_request.clone();
                let user_id = user.id.clone();
                let service_id = service.id.clone();
                let scopes = scopes.clone();
                let event = grant_failure_event.clone();
                Box::pin(async move {
                    ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                        transaction,
                        &audit_actor,
                        &request.state,
                        &user_id,
                        &service_id,
                        "missing-connected-account",
                        "github",
                        &scopes,
                        vec![event],
                    )
                    .await
                })
            },
        )
        .await;
        assert!(matches!(grant_failure, Err(AppError::NotFound(_))));
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &grant_failure_request.state,
            &user.id,
        )
        .await
        .expect("read grant-failure request")
        .is_some());
        assert_eq!(
            audit_outbox::Entity::find()
                .count(&db)
                .await
                .expect("count grant-failure outbox rows")
                + organization_audit_log::Entity::find()
                    .count(&db)
                    .await
                    .expect("count grant-failure delivered audits"),
            0
        );

        let audit_failure_request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &user.id,
            &service.id,
            "github",
            Some(&account.id),
            &scopes,
            "https://client.example/callback",
            None,
        )
        .await
        .expect("create audit-failure request");
        let audit_before_failure =
            OrgAuditBuilder::new(&org.id, Some(&user.id), "provider_grant.created")
                .target("connected_account", &account.id)
                .build();
        let audit_failure = with_retrying_transaction(
            &db,
            &db,
            "provider_request_injected_audit_failure",
            |transaction| {
                let audit_actor = audit_actor.clone();
                let request = audit_failure_request.clone();
                let user_id = user.id.clone();
                let service_id = service.id.clone();
                let account_id = account.id.clone();
                let scopes = scopes.clone();
                let audit_before_failure = audit_before_failure.clone();
                Box::pin(async move {
                    ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                        transaction,
                        &audit_actor,
                        &request.state,
                        &user_id,
                        &service_id,
                        &account_id,
                        "github",
                        &scopes,
                        vec![audit_before_failure, Default::default()],
                    )
                    .await
                })
            },
        )
        .await;
        assert!(matches!(audit_failure, Err(AppError::Audit(_))));
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &audit_failure_request.state,
            &user.id,
        )
        .await
        .expect("read audit-failure request")
        .is_some());
        assert!(ServiceProviderGrantStore::find_active(
            DB::Conn(&db),
            &user.id,
            &service.id,
            &account.id,
        )
        .await
        .expect("read rolled-back grant")
        .is_none());
        assert_eq!(
            audit_outbox::Entity::find()
                .count(&db)
                .await
                .expect("count audit-failure outbox rows")
                + organization_audit_log::Entity::find()
                    .count(&db)
                    .await
                    .expect("count audit-failure delivered audits"),
            0
        );

        let inactive_parent_request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &user.id,
            &service.id,
            "github",
            Some(&account.id),
            &scopes,
            "https://client.example/callback",
            None,
        )
        .await
        .expect("create inactive-parent request");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend organization");
        let inactive_parent = with_retrying_transaction(
            &db,
            &db,
            "provider_request_inactive_parent",
            |transaction| {
                let audit_actor = audit_actor.clone();
                let request = inactive_parent_request.clone();
                let user_id = user.id.clone();
                let service_id = service.id.clone();
                let account_id = account.id.clone();
                let scopes = scopes.clone();
                let event = OrgAuditBuilder::new(
                    &org.id,
                    Some(&user.id),
                    "provider_token_request.completed",
                )
                .target("provider_token_request", &inactive_parent_request.state)
                .build();
                Box::pin(async move {
                    ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                        transaction,
                        &audit_actor,
                        &request.state,
                        &user_id,
                        &service_id,
                        &account_id,
                        "github",
                        &scopes,
                        vec![event],
                    )
                    .await
                })
            },
        )
        .await;
        assert!(matches!(inactive_parent, Err(AppError::Forbidden(_))));
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &inactive_parent_request.state,
            &user.id,
        )
        .await
        .expect("read inactive-parent request")
        .is_some());
        assert!(ServiceProviderGrantStore::find_active(
            DB::Conn(&db),
            &user.id,
            &service.id,
            &account.id,
        )
        .await
        .expect("read denied inactive-parent grant")
        .is_none());
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("reactivate organization");

        IdentityStore::delete(DB::Conn(&db), &identity.id)
            .await
            .expect("remove service identity");
        let removed_entitlement_request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &user.id,
            &service.id,
            "github",
            Some(&account.id),
            &scopes,
            "https://client.example/callback",
            None,
        )
        .await
        .expect("create removed-entitlement request");
        let removed_entitlement = with_retrying_transaction(
            &db,
            &db,
            "provider_request_removed_entitlement",
            |transaction| {
                let audit_actor = audit_actor.clone();
                let request = removed_entitlement_request.clone();
                let user_id = user.id.clone();
                let service_id = service.id.clone();
                let account_id = account.id.clone();
                let scopes = scopes.clone();
                let event = OrgAuditBuilder::new(
                    &org.id,
                    Some(&user.id),
                    "provider_token_request.completed",
                )
                .target("provider_token_request", &removed_entitlement_request.state)
                .build();
                Box::pin(async move {
                    ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                        transaction,
                        &audit_actor,
                        &request.state,
                        &user_id,
                        &service_id,
                        &account_id,
                        "github",
                        &scopes,
                        vec![event],
                    )
                    .await
                })
            },
        )
        .await;
        assert!(matches!(removed_entitlement, Err(AppError::Forbidden(_))));
        assert!(ProviderTokenRequestStore::find_active_for_user(
            DB::Conn(&db),
            &removed_entitlement_request.state,
            &user.id,
        )
        .await
        .expect("read removed-entitlement request")
        .is_some());
        assert!(ServiceProviderGrantStore::find_active(
            DB::Conn(&db),
            &user.id,
            &service.id,
            &account.id,
        )
        .await
        .expect("read denied removed-entitlement grant")
        .is_none());
        assert_eq!(
            audit_outbox::Entity::find()
                .count(&db)
                .await
                .expect("count denied-entitlement outbox rows")
                + organization_audit_log::Entity::find()
                    .count(&db)
                    .await
                    .expect("count denied-entitlement delivered audits"),
            0
        );
        IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "password",
            &user.id,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service.id),
        )
        .await
        .expect("restore exact service identity");

        let concurrent_request = ProviderTokenRequestStore::create(
            DB::Conn(&db),
            &user.id,
            &service.id,
            "github",
            Some(&account.id),
            &scopes,
            "https://client.example/callback",
            None,
        )
        .await
        .expect("create concurrent request");
        let concurrent_event =
            OrgAuditBuilder::new(&org.id, Some(&user.id), "provider_token_request.completed")
                .target("provider_token_request", &concurrent_request.state)
                .build();
        let complete_once = || {
            with_retrying_transaction(&db, &db, "provider_request_concurrent", |transaction| {
                let audit_actor = audit_actor.clone();
                let request = concurrent_request.clone();
                let user_id = user.id.clone();
                let service_id = service.id.clone();
                let account_id = account.id.clone();
                let scopes = scopes.clone();
                let event = concurrent_event.clone();
                Box::pin(async move {
                    ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                        transaction,
                        &audit_actor,
                        &request.state,
                        &user_id,
                        &service_id,
                        &account_id,
                        "github",
                        &scopes,
                        vec![event],
                    )
                    .await
                })
            })
        };
        let (first, second) = tokio::join!(complete_once(), complete_once());
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(
            service_provider_grants::Entity::find()
                .filter(service_provider_grants::Column::UserId.eq(&user.id))
                .filter(service_provider_grants::Column::ServiceId.eq(&service.id))
                .filter(service_provider_grants::Column::ConnectedAccountId.eq(&account.id))
                .count(&db)
                .await
                .expect("count committed grants"),
            1
        );

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }
}
