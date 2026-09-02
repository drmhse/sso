use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_index(
            manager,
            "idx_sessions_refresh_token",
            Sessions::Table,
            &[Sessions::RefreshToken],
        )
        .await?;
        create_index(
            manager,
            "idx_sessions_user_expires",
            Sessions::Table,
            &[Sessions::UserId, Sessions::ExpiresAt],
        )
        .await?;
        create_index(
            manager,
            "idx_sessions_user_service_expires",
            Sessions::Table,
            &[Sessions::UserId, Sessions::ServiceId, Sessions::ExpiresAt],
        )
        .await?;
        create_index(
            manager,
            "idx_sessions_user_org_slug",
            Sessions::Table,
            &[Sessions::UserId, Sessions::OrgSlug],
        )
        .await?;

        create_index(
            manager,
            "idx_device_codes_expires",
            DeviceCodes::Table,
            &[DeviceCodes::ExpiresAt],
        )
        .await?;
        create_index(
            manager,
            "idx_device_codes_org_service_status",
            DeviceCodes::Table,
            &[
                DeviceCodes::OrgSlug,
                DeviceCodes::ServiceSlug,
                DeviceCodes::Status,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_oauth_states_expires",
            OauthStates::Table,
            &[OauthStates::ExpiresAt],
        )
        .await?;

        create_index(
            manager,
            "idx_webhooks_org_active",
            Webhooks::Table,
            &[Webhooks::OrgId, Webhooks::IsActive],
        )
        .await?;
        create_index(
            manager,
            "idx_webhook_deliveries_pending",
            WebhookDeliveries::Table,
            &[
                WebhookDeliveries::Delivered,
                WebhookDeliveries::NextRetryAt,
                WebhookDeliveries::CreatedAt,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_webhook_deliveries_cleanup",
            WebhookDeliveries::Table,
            &[WebhookDeliveries::Delivered, WebhookDeliveries::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_webhook_deliveries_webhook_created",
            WebhookDeliveries::Table,
            &[WebhookDeliveries::WebhookId, WebhookDeliveries::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_webhook_deliveries_webhook_event_delivered_created",
            WebhookDeliveries::Table,
            &[
                WebhookDeliveries::WebhookId,
                WebhookDeliveries::EventType,
                WebhookDeliveries::Delivered,
                WebhookDeliveries::CreatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_login_events_service_created",
            LoginEvents::Table,
            &[LoginEvents::ServiceId, LoginEvents::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_login_events_user_created",
            LoginEvents::Table,
            &[LoginEvents::UserId, LoginEvents::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_login_events_ip_created",
            LoginEvents::Table,
            &[LoginEvents::IpAddress, LoginEvents::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_login_events_user_org_created",
            LoginEvents::Table,
            &[
                LoginEvents::UserId,
                LoginEvents::OrgId,
                LoginEvents::CreatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_services_org_type_created",
            Services::Table,
            &[Services::OrgId, Services::ServiceType, Services::CreatedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_plans_service_created",
            Plans::Table,
            &[Plans::ServiceId, Plans::CreatedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_subscriptions_service_status_period",
            Subscriptions::Table,
            &[
                Subscriptions::ServiceId,
                Subscriptions::Status,
                Subscriptions::CurrentPeriodEnd,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_subscriptions_plan_status",
            Subscriptions::Table,
            &[Subscriptions::PlanId, Subscriptions::Status],
        )
        .await?;
        create_index(
            manager,
            "idx_subscriptions_user_service_status",
            Subscriptions::Table,
            &[
                Subscriptions::UserId,
                Subscriptions::ServiceId,
                Subscriptions::Status,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_subscriptions_service_user",
            Subscriptions::Table,
            &[Subscriptions::ServiceId, Subscriptions::UserId],
        )
        .await?;
        create_index(
            manager,
            "idx_subscriptions_user_created",
            Subscriptions::Table,
            &[Subscriptions::UserId, Subscriptions::CreatedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_identities_org_user",
            Identities::Table,
            &[Identities::IssuingOrgId, Identities::UserId],
        )
        .await?;
        create_index(
            manager,
            "idx_identities_service_user",
            Identities::Table,
            &[Identities::IssuingServiceId, Identities::UserId],
        )
        .await?;
        create_index(
            manager,
            "idx_identities_service_created_user",
            Identities::Table,
            &[
                Identities::IssuingServiceId,
                Identities::CreatedAt,
                Identities::UserId,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_identities_user_org_service_created",
            Identities::Table,
            &[
                Identities::UserId,
                Identities::IssuingOrgId,
                Identities::IssuingServiceId,
                Identities::CreatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_api_keys_service_created",
            ApiKeys::Table,
            &[ApiKeys::ServiceId, ApiKeys::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_api_keys_expires",
            ApiKeys::Table,
            &[ApiKeys::ExpiresAt],
        )
        .await?;

        create_index(
            manager,
            "idx_connected_accounts_user_status_provider_updated",
            ConnectedAccounts::Table,
            &[
                ConnectedAccounts::UserId,
                ConnectedAccounts::Status,
                ConnectedAccounts::Provider,
                ConnectedAccounts::UpdatedAt,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_connected_accounts_user_provider_status_updated",
            ConnectedAccounts::Table,
            &[
                ConnectedAccounts::UserId,
                ConnectedAccounts::Provider,
                ConnectedAccounts::Status,
                ConnectedAccounts::UpdatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_service_provider_grants_user_service_status_account",
            ServiceProviderGrants::Table,
            &[
                ServiceProviderGrants::UserId,
                ServiceProviderGrants::ServiceId,
                ServiceProviderGrants::Status,
                ServiceProviderGrants::ConnectedAccountId,
                ServiceProviderGrants::GrantedAt,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_service_provider_grants_user_service_provider_status",
            ServiceProviderGrants::Table,
            &[
                ServiceProviderGrants::UserId,
                ServiceProviderGrants::ServiceId,
                ServiceProviderGrants::Provider,
                ServiceProviderGrants::Status,
                ServiceProviderGrants::GrantedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_user_devices_user_last_seen",
            UserDevices::Table,
            &[UserDevices::UserId, UserDevices::LastSeenAt],
        )
        .await?;
        create_index(
            manager,
            "idx_user_devices_user_created",
            UserDevices::Table,
            &[UserDevices::UserId, UserDevices::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_user_devices_user_name",
            UserDevices::Table,
            &[UserDevices::UserId, UserDevices::Name],
        )
        .await?;
        create_index(
            manager,
            "idx_user_devices_expires",
            UserDevices::Table,
            &[UserDevices::ExpiresAt],
        )
        .await?;

        create_index(
            manager,
            "idx_permissions_subject",
            Permissions::Table,
            &[Permissions::SubjectType, Permissions::SubjectId],
        )
        .await?;

        create_index(
            manager,
            "idx_memberships_user_created",
            Memberships::Table,
            &[Memberships::UserId, Memberships::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_memberships_org_role_created",
            Memberships::Table,
            &[
                Memberships::OrgId,
                Memberships::Role,
                Memberships::CreatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_org_invitations_email_status_created",
            OrganizationInvitations::Table,
            &[
                OrganizationInvitations::Email,
                OrganizationInvitations::Status,
                OrganizationInvitations::CreatedAt,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_org_invitations_org_created",
            OrganizationInvitations::Table,
            &[
                OrganizationInvitations::OrgId,
                OrganizationInvitations::CreatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_scim_tokens_org_created",
            ScimTokens::Table,
            &[ScimTokens::OrgId, ScimTokens::CreatedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_saml_states_expires",
            SamlStates::Table,
            &[SamlStates::ExpiresAt],
        )
        .await?;

        create_index(
            manager,
            "idx_token_refresh_locks_expires",
            TokenRefreshLocks::Table,
            &[TokenRefreshLocks::ExpiresAt],
        )
        .await?;

        create_index(
            manager,
            "idx_system_jobs_completed_at",
            SystemJobs::Table,
            &[SystemJobs::Status, SystemJobs::CompletedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_users_created_at",
            Users::Table,
            &[Users::CreatedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_password_reset_token_used",
            PasswordResetTokens::Table,
            &[PasswordResetTokens::TokenHash, PasswordResetTokens::Used],
        )
        .await?;
        create_index(
            manager,
            "idx_password_reset_expires",
            PasswordResetTokens::Table,
            &[PasswordResetTokens::ExpiresAt],
        )
        .await?;

        create_index(
            manager,
            "idx_user_totp_enabled",
            UserTotpSecrets::Table,
            &[UserTotpSecrets::Enabled],
        )
        .await?;
        create_index(
            manager,
            "idx_user_totp_enabled_user",
            UserTotpSecrets::Table,
            &[UserTotpSecrets::Enabled, UserTotpSecrets::UserId],
        )
        .await?;

        create_index(
            manager,
            "idx_totp_backup_codes_user_used",
            TotpBackupCodes::Table,
            &[TotpBackupCodes::UserId, TotpBackupCodes::Used],
        )
        .await?;

        create_index(
            manager,
            "idx_org_audit_org_created",
            OrganizationAuditLog::Table,
            &[OrganizationAuditLog::OrgId, OrganizationAuditLog::CreatedAt],
        )
        .await?;
        create_index(
            manager,
            "idx_org_audit_org_action_created",
            OrganizationAuditLog::Table,
            &[
                OrganizationAuditLog::OrgId,
                OrganizationAuditLog::Action,
                OrganizationAuditLog::CreatedAt,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_org_audit_org_target_created",
            OrganizationAuditLog::Table,
            &[
                OrganizationAuditLog::OrgId,
                OrganizationAuditLog::TargetType,
                OrganizationAuditLog::TargetId,
                OrganizationAuditLog::CreatedAt,
            ],
        )
        .await?;

        create_index(
            manager,
            "idx_mfa_audit_created",
            MfaAuditLog::Table,
            &[MfaAuditLog::CreatedAt],
        )
        .await?;

        create_index(
            manager,
            "idx_mfa_feature_usage_user_timestamp",
            MfaFeatureUsage::Table,
            &[MfaFeatureUsage::UserId, MfaFeatureUsage::Timestamp],
        )
        .await?;
        create_index(
            manager,
            "idx_mfa_feature_usage_org_timestamp",
            MfaFeatureUsage::Table,
            &[MfaFeatureUsage::OrgId, MfaFeatureUsage::Timestamp],
        )
        .await?;

        create_index(
            manager,
            "idx_mfa_failures_lookup",
            MfaFailurePatterns::Table,
            &[
                MfaFailurePatterns::FailureType,
                MfaFailurePatterns::OrgId,
                MfaFailurePatterns::UserId,
                MfaFailurePatterns::IpAddress,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_mfa_failures_suspicious_org_seen",
            MfaFailurePatterns::Table,
            &[
                MfaFailurePatterns::IsSuspicious,
                MfaFailurePatterns::OrgId,
                MfaFailurePatterns::LastSeenAt,
            ],
        )
        .await?;
        create_index(
            manager,
            "idx_mfa_failures_suspicious_user_ip",
            MfaFailurePatterns::Table,
            &[
                MfaFailurePatterns::IsSuspicious,
                MfaFailurePatterns::UserId,
                MfaFailurePatterns::IpAddress,
            ],
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // MySQL may replace implicit single-column FK indexes with the broader
        // access indexes below. Restore dedicated FK support before removing
        // the indexes introduced by this migration.
        if manager.get_database_backend() == sea_orm_migration::sea_orm::DbBackend::MySql {
            for (table, column, name) in [
                (
                    TotpBackupCodes::Table.into_iden(),
                    TotpBackupCodes::UserId.into_iden(),
                    "fk_backup_codes_user",
                ),
                (
                    ScimTokens::Table.into_iden(),
                    ScimTokens::OrgId.into_iden(),
                    "fk_scim_tokens_org",
                ),
                (
                    ApiKeys::Table.into_iden(),
                    ApiKeys::ServiceId.into_iden(),
                    "fk_api_keys_service",
                ),
                (
                    Subscriptions::Table.into_iden(),
                    Subscriptions::UserId.into_iden(),
                    "fk_subscriptions_user",
                ),
                (
                    Subscriptions::Table.into_iden(),
                    Subscriptions::ServiceId.into_iden(),
                    "fk_subscriptions_service",
                ),
                (
                    Subscriptions::Table.into_iden(),
                    Subscriptions::PlanId.into_iden(),
                    "fk_subscriptions_plan",
                ),
                (
                    LoginEvents::Table.into_iden(),
                    LoginEvents::UserId.into_iden(),
                    "fk_login_events_user",
                ),
                (
                    LoginEvents::Table.into_iden(),
                    LoginEvents::ServiceId.into_iden(),
                    "fk_login_events_service",
                ),
                (
                    WebhookDeliveries::Table.into_iden(),
                    WebhookDeliveries::WebhookId.into_iden(),
                    "fk_webhook_deliveries_webhook",
                ),
                (
                    Sessions::Table.into_iden(),
                    Sessions::UserId.into_iden(),
                    "fk_sessions_user",
                ),
                (
                    OrganizationAuditLog::Table.into_iden(),
                    OrganizationAuditLog::OrgId.into_iden(),
                    "fk_org_audit_org",
                ),
            ] {
                let table_name = table.to_string();
                if !manager.has_index(&table_name, name).await? {
                    manager
                        .create_index(
                            Index::create()
                                .name(name)
                                .table(table)
                                .col(column)
                                .to_owned(),
                        )
                        .await?;
                }
            }
        }

        for (table, name) in [
            (
                MfaFailurePatterns::Table.into_iden(),
                "idx_mfa_failures_suspicious_user_ip",
            ),
            (
                MfaFailurePatterns::Table.into_iden(),
                "idx_mfa_failures_suspicious_org_seen",
            ),
            (
                MfaFailurePatterns::Table.into_iden(),
                "idx_mfa_failures_lookup",
            ),
            (
                MfaFeatureUsage::Table.into_iden(),
                "idx_mfa_feature_usage_org_timestamp",
            ),
            (
                MfaFeatureUsage::Table.into_iden(),
                "idx_mfa_feature_usage_user_timestamp",
            ),
            (MfaAuditLog::Table.into_iden(), "idx_mfa_audit_created"),
            (
                OrganizationAuditLog::Table.into_iden(),
                "idx_org_audit_org_target_created",
            ),
            (
                OrganizationAuditLog::Table.into_iden(),
                "idx_org_audit_org_action_created",
            ),
            (
                OrganizationAuditLog::Table.into_iden(),
                "idx_org_audit_org_created",
            ),
            (
                TotpBackupCodes::Table.into_iden(),
                "idx_totp_backup_codes_user_used",
            ),
            (
                UserTotpSecrets::Table.into_iden(),
                "idx_user_totp_enabled_user",
            ),
            (UserTotpSecrets::Table.into_iden(), "idx_user_totp_enabled"),
            (
                PasswordResetTokens::Table.into_iden(),
                "idx_password_reset_expires",
            ),
            (
                PasswordResetTokens::Table.into_iden(),
                "idx_password_reset_token_used",
            ),
            (Users::Table.into_iden(), "idx_users_created_at"),
            (
                SystemJobs::Table.into_iden(),
                "idx_system_jobs_completed_at",
            ),
            (
                TokenRefreshLocks::Table.into_iden(),
                "idx_token_refresh_locks_expires",
            ),
            (SamlStates::Table.into_iden(), "idx_saml_states_expires"),
            (ScimTokens::Table.into_iden(), "idx_scim_tokens_org_created"),
            (
                OrganizationInvitations::Table.into_iden(),
                "idx_org_invitations_org_created",
            ),
            (
                OrganizationInvitations::Table.into_iden(),
                "idx_org_invitations_email_status_created",
            ),
            (
                Memberships::Table.into_iden(),
                "idx_memberships_org_role_created",
            ),
            (
                Memberships::Table.into_iden(),
                "idx_memberships_user_created",
            ),
            (Permissions::Table.into_iden(), "idx_permissions_subject"),
            (UserDevices::Table.into_iden(), "idx_user_devices_expires"),
            (UserDevices::Table.into_iden(), "idx_user_devices_user_name"),
            (
                UserDevices::Table.into_iden(),
                "idx_user_devices_user_created",
            ),
            (
                UserDevices::Table.into_iden(),
                "idx_user_devices_user_last_seen",
            ),
            (ApiKeys::Table.into_iden(), "idx_api_keys_expires"),
            (ApiKeys::Table.into_iden(), "idx_api_keys_service_created"),
            (
                ServiceProviderGrants::Table.into_iden(),
                "idx_service_provider_grants_user_service_provider_status",
            ),
            (
                ServiceProviderGrants::Table.into_iden(),
                "idx_service_provider_grants_user_service_status_account",
            ),
            (
                ConnectedAccounts::Table.into_iden(),
                "idx_connected_accounts_user_provider_status_updated",
            ),
            (
                ConnectedAccounts::Table.into_iden(),
                "idx_connected_accounts_user_status_provider_updated",
            ),
            (
                Subscriptions::Table.into_iden(),
                "idx_subscriptions_user_service_status",
            ),
            (
                Identities::Table.into_iden(),
                "idx_identities_user_org_service_created",
            ),
            (
                Identities::Table.into_iden(),
                "idx_identities_service_created_user",
            ),
            (Identities::Table.into_iden(), "idx_identities_service_user"),
            (Identities::Table.into_iden(), "idx_identities_org_user"),
            (
                Subscriptions::Table.into_iden(),
                "idx_subscriptions_user_created",
            ),
            (
                Subscriptions::Table.into_iden(),
                "idx_subscriptions_service_user",
            ),
            (
                Subscriptions::Table.into_iden(),
                "idx_subscriptions_plan_status",
            ),
            (
                Subscriptions::Table.into_iden(),
                "idx_subscriptions_service_status_period",
            ),
            (Plans::Table.into_iden(), "idx_plans_service_created"),
            (Services::Table.into_iden(), "idx_services_org_type_created"),
            (
                LoginEvents::Table.into_iden(),
                "idx_login_events_user_org_created",
            ),
            (
                LoginEvents::Table.into_iden(),
                "idx_login_events_ip_created",
            ),
            (
                LoginEvents::Table.into_iden(),
                "idx_login_events_user_created",
            ),
            (
                LoginEvents::Table.into_iden(),
                "idx_login_events_service_created",
            ),
            (
                WebhookDeliveries::Table.into_iden(),
                "idx_webhook_deliveries_webhook_event_delivered_created",
            ),
            (
                WebhookDeliveries::Table.into_iden(),
                "idx_webhook_deliveries_webhook_created",
            ),
            (
                WebhookDeliveries::Table.into_iden(),
                "idx_webhook_deliveries_cleanup",
            ),
            (
                WebhookDeliveries::Table.into_iden(),
                "idx_webhook_deliveries_pending",
            ),
            (Webhooks::Table.into_iden(), "idx_webhooks_org_active"),
            (OauthStates::Table.into_iden(), "idx_oauth_states_expires"),
            (
                DeviceCodes::Table.into_iden(),
                "idx_device_codes_org_service_status",
            ),
            (DeviceCodes::Table.into_iden(), "idx_device_codes_expires"),
            (Sessions::Table.into_iden(), "idx_sessions_user_org_slug"),
            (
                Sessions::Table.into_iden(),
                "idx_sessions_user_service_expires",
            ),
            (Sessions::Table.into_iden(), "idx_sessions_user_expires"),
            (Sessions::Table.into_iden(), "idx_sessions_refresh_token"),
        ] {
            let table_name = table.to_string();
            if manager.has_index(&table_name, name).await? {
                manager
                    .drop_index(Index::drop().name(name).table(table).to_owned())
                    .await?;
            }
        }

        Ok(())
    }
}

async fn create_index<T, C>(
    manager: &SchemaManager<'_>,
    name: &str,
    table: T,
    columns: &[C],
) -> Result<(), DbErr>
where
    T: Iden + Copy + 'static,
    C: Iden + Copy + 'static,
{
    let table_name = table.to_string();
    if manager.has_index(&table_name, name).await? {
        return Ok(());
    }

    let mut index = Index::create();
    index.name(name).table(table);
    for column in columns {
        index.col(*column);
    }
    manager.create_index(index.clone()).await
}

#[derive(DeriveIden, Copy, Clone)]
enum Sessions {
    Table,
    UserId,
    RefreshToken,
    ExpiresAt,
    ServiceId,
    OrgSlug,
}

#[derive(DeriveIden, Copy, Clone)]
enum DeviceCodes {
    Table,
    OrgSlug,
    ServiceSlug,
    Status,
    ExpiresAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum OauthStates {
    Table,
    ExpiresAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Webhooks {
    Table,
    OrgId,
    IsActive,
}

#[derive(DeriveIden, Copy, Clone)]
enum WebhookDeliveries {
    Table,
    WebhookId,
    EventType,
    Delivered,
    NextRetryAt,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum LoginEvents {
    Table,
    ServiceId,
    UserId,
    OrgId,
    IpAddress,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Services {
    Table,
    OrgId,
    ServiceType,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Plans {
    Table,
    ServiceId,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Subscriptions {
    Table,
    UserId,
    ServiceId,
    PlanId,
    Status,
    CurrentPeriodEnd,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Identities {
    Table,
    UserId,
    IssuingOrgId,
    IssuingServiceId,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum ApiKeys {
    Table,
    ServiceId,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum ConnectedAccounts {
    Table,
    UserId,
    Provider,
    Status,
    UpdatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum ServiceProviderGrants {
    Table,
    UserId,
    ServiceId,
    ConnectedAccountId,
    Provider,
    Status,
    GrantedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum UserDevices {
    Table,
    UserId,
    LastSeenAt,
    CreatedAt,
    Name,
    ExpiresAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Permissions {
    Table,
    SubjectType,
    SubjectId,
}

#[derive(DeriveIden, Copy, Clone)]
enum Memberships {
    Table,
    UserId,
    OrgId,
    Role,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum OrganizationInvitations {
    Table,
    OrgId,
    Email,
    Status,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum ScimTokens {
    Table,
    OrgId,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum SamlStates {
    Table,
    ExpiresAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum TokenRefreshLocks {
    Table,
    ExpiresAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum SystemJobs {
    Table,
    Status,
    CompletedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum Users {
    Table,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum PasswordResetTokens {
    Table,
    TokenHash,
    ExpiresAt,
    Used,
}

#[derive(DeriveIden, Copy, Clone)]
enum UserTotpSecrets {
    Table,
    Enabled,
    UserId,
}

#[derive(DeriveIden, Copy, Clone)]
enum TotpBackupCodes {
    Table,
    UserId,
    Used,
}

#[derive(DeriveIden, Copy, Clone)]
enum OrganizationAuditLog {
    Table,
    OrgId,
    Action,
    TargetType,
    TargetId,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum MfaAuditLog {
    Table,
    CreatedAt,
}

#[derive(DeriveIden, Copy, Clone)]
enum MfaFeatureUsage {
    Table,
    OrgId,
    UserId,
    Timestamp,
}

#[derive(DeriveIden, Copy, Clone)]
enum MfaFailurePatterns {
    Table,
    OrgId,
    UserId,
    IpAddress,
    FailureType,
    LastSeenAt,
    IsSuspicious,
}
