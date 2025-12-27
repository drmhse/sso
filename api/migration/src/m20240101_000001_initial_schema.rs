use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        // ============================================================================
        // 1. USERS & IDENTITIES
        // ============================================================================

        manager.create_table(Table::create()
            .table(Users::Table).if_not_exists()
            .col(ColumnDef::new(Users::Id).string_len(36).not_null().primary_key())
            .col(ColumnDef::new(Users::Email).string_len(254).not_null().unique_key())
            .col(ColumnDef::new(Users::IsPlatformOwner).boolean().not_null().default(false))
            .col(ColumnDef::new(Users::PasswordHash).string())
            .col(ColumnDef::new(Users::EmailVerifiedAt).date_time().null())
            .col(ColumnDef::new(Users::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(Users::UpdatedAt).date_time().null())
            .col(ColumnDef::new(Users::DeletedAt).date_time().null())
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_users_deleted_at").table(Users::Table).col(Users::DeletedAt).to_owned()).await?;
        manager.create_index(Index::create().name("idx_users_updated_at").table(Users::Table).col(Users::UpdatedAt).to_owned()).await?;

        manager.create_table(Table::create()
            .table(Identities::Table).if_not_exists()
            .col(ColumnDef::new(Identities::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Identities::UserId).string_len(36).not_null())
            .col(ColumnDef::new(Identities::Provider).string_len(100).not_null())
            .col(ColumnDef::new(Identities::ProviderUserId).string_len(255).not_null())
            .col(ColumnDef::new(Identities::AccessToken).text())
            .col(ColumnDef::new(Identities::RefreshToken).text())
            .col(ColumnDef::new(Identities::AccessTokenEncrypted).blob())
            .col(ColumnDef::new(Identities::RefreshTokenEncrypted).blob())
            .col(ColumnDef::new(Identities::EncryptionKeyId).string().default("default"))
            .col(ColumnDef::new(Identities::ExpiresAt).date_time().null())
            .col(ColumnDef::new(Identities::Scopes).text())
            .col(ColumnDef::new(Identities::LastRefreshedAt).date_time().null())
            .col(ColumnDef::new(Identities::IssuingOrgId).string_len(36))
            .col(ColumnDef::new(Identities::IssuingServiceId).string_len(36))
            .col(ColumnDef::new(Identities::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_identities_user").from(Identities::Table, Identities::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_identities_user").table(Identities::Table).col(Identities::UserId).to_owned()).await?;
        manager.create_index(Index::create().name("idx_identities_provider_user").table(Identities::Table).col(Identities::Provider).col(Identities::ProviderUserId).to_owned()).await?;

        // Partial indexes for identities (SQLite and PostgreSQL)
        // if matches!(backend, sea_orm::DatabaseBackend::Sqlite | sea_orm::DatabaseBackend::Postgres) {
        //     db.execute_unprepared("CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_platform_unique ON identities(user_id, provider) WHERE issuing_org_id IS NULL AND issuing_service_id IS NULL").await?;
        //     db.execute_unprepared("CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_service_unique ON identities(user_id, provider, issuing_org_id, issuing_service_id) WHERE issuing_org_id IS NOT NULL AND issuing_service_id IS NOT NULL").await?;
        // }

        // ============================================================================
        // 2. SESSIONS & AUTHENTICATION STATE
        // ============================================================================

        manager.create_table(Table::create()
            .table(Sessions::Table).if_not_exists()
            .col(ColumnDef::new(Sessions::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Sessions::UserId).string_len(36).not_null())
            .col(ColumnDef::new(Sessions::TokenHash).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(Sessions::ExpiresAt).date_time().not_null())
            .col(ColumnDef::new(Sessions::RefreshToken).string())
            .col(ColumnDef::new(Sessions::RefreshTokenExpiresAt).date_time().null())
            .col(ColumnDef::new(Sessions::OrgSlug).string_len(100))
            .col(ColumnDef::new(Sessions::ServiceId).string_len(36))
            .col(ColumnDef::new(Sessions::UserAgent).text())
            .col(ColumnDef::new(Sessions::IpAddress).string_len(50))
            .col(ColumnDef::new(Sessions::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_sessions_user").from(Sessions::Table, Sessions::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_sessions_token").table(Sessions::Table).col(Sessions::TokenHash).to_owned()).await?;
        manager.create_index(Index::create().name("idx_sessions_expires").table(Sessions::Table).col(Sessions::ExpiresAt).to_owned()).await?;

        manager.create_table(Table::create()
            .table(DeviceCodes::Table).if_not_exists()
            .col(ColumnDef::new(DeviceCodes::Id).string().not_null().primary_key())
            .col(ColumnDef::new(DeviceCodes::DeviceCode).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(DeviceCodes::UserCode).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(DeviceCodes::ClientId).string().not_null())
            .col(ColumnDef::new(DeviceCodes::OrgSlug).string_len(100).not_null())
            .col(ColumnDef::new(DeviceCodes::ServiceSlug).string_len(100).not_null())
            .col(ColumnDef::new(DeviceCodes::ExpiresAt).date_time().not_null())
            .col(ColumnDef::new(DeviceCodes::UserId).string_len(36))
            .col(ColumnDef::new(DeviceCodes::Status).string_len(50).not_null().default("pending"))
            .foreign_key(ForeignKey::create().name("fk_device_codes_user").from(DeviceCodes::Table, DeviceCodes::UserId).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        manager.create_table(Table::create()
            .table(OauthStates::Table).if_not_exists()
            .col(ColumnDef::new(OauthStates::State).string().not_null().primary_key())
            .col(ColumnDef::new(OauthStates::PkceVerifier).text())
            .col(ColumnDef::new(OauthStates::ServiceId).string_len(36))
            .col(ColumnDef::new(OauthStates::RedirectUri).text())
            .col(ColumnDef::new(OauthStates::OrgSlug).string_len(100))
            .col(ColumnDef::new(OauthStates::ServiceSlug).string_len(100))
            .col(ColumnDef::new(OauthStates::IsAdminFlow).boolean().not_null().default(false))
            .col(ColumnDef::new(OauthStates::UserIdForLinking).string())
            .col(ColumnDef::new(OauthStates::DeviceUserCode).string())
            .col(ColumnDef::new(OauthStates::SamlStateId).string())
            .col(ColumnDef::new(OauthStates::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(OauthStates::ExpiresAt).date_time().not_null())
            .foreign_key(ForeignKey::create().name("fk_oauth_states_user").from(OauthStates::Table, OauthStates::UserIdForLinking).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        manager.create_table(Table::create()
            .table(TokenRefreshLocks::Table).if_not_exists()
            .col(ColumnDef::new(TokenRefreshLocks::UserId).string_len(36).not_null().primary_key())
            .col(ColumnDef::new(TokenRefreshLocks::AcquiredAt).date_time().not_null())
            .col(ColumnDef::new(TokenRefreshLocks::ExpiresAt).date_time().not_null())
            .to_owned()
        ).await?;

        manager.create_table(Table::create()
            .table(MagicLinkTokens::Table).if_not_exists()
            .col(ColumnDef::new(MagicLinkTokens::TokenHash).string().not_null().primary_key())
            .col(ColumnDef::new(MagicLinkTokens::UserId).string_len(36).null())
            .col(ColumnDef::new(MagicLinkTokens::Email).string_len(254).not_null())
            .col(ColumnDef::new(MagicLinkTokens::Context).string().not_null())
            .col(ColumnDef::new(MagicLinkTokens::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(MagicLinkTokens::ExpiresAt).date_time().not_null())
            .foreign_key(ForeignKey::create().name("fk_magic_link_user").from(MagicLinkTokens::Table, MagicLinkTokens::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_magic_link_tokens_email").table(MagicLinkTokens::Table).col(MagicLinkTokens::Email).to_owned()).await?;
        manager.create_index(Index::create().name("idx_magic_link_tokens_expires").table(MagicLinkTokens::Table).col(MagicLinkTokens::ExpiresAt).to_owned()).await?;

        // ============================================================================
        // 3. PASSWORD & MFA
        // ============================================================================

        manager.create_table(Table::create()
            .table(PasswordResetTokens::Table).if_not_exists()
            .col(ColumnDef::new(PasswordResetTokens::Id).string().not_null().primary_key())
            .col(ColumnDef::new(PasswordResetTokens::UserId).string_len(36).not_null())
            .col(ColumnDef::new(PasswordResetTokens::TokenHash).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(PasswordResetTokens::ExpiresAt).date_time().not_null())
            .col(ColumnDef::new(PasswordResetTokens::Used).boolean().not_null().default(false))
            .col(ColumnDef::new(PasswordResetTokens::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_password_reset_user").from(PasswordResetTokens::Table, PasswordResetTokens::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_table(Table::create()
            .table(UserTotpSecrets::Table).if_not_exists()
            .col(ColumnDef::new(UserTotpSecrets::Id).string().not_null().primary_key())
            .col(ColumnDef::new(UserTotpSecrets::UserId).string_len(36).not_null().unique_key())
            .col(ColumnDef::new(UserTotpSecrets::SecretEncrypted).blob().not_null())
            .col(ColumnDef::new(UserTotpSecrets::EncryptionKeyId).string().not_null().default("default"))
            .col(ColumnDef::new(UserTotpSecrets::Enabled).boolean().not_null().default(false))
            .col(ColumnDef::new(UserTotpSecrets::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(UserTotpSecrets::EnabledAt).date_time().null())
            .foreign_key(ForeignKey::create().name("fk_totp_secrets_user").from(UserTotpSecrets::Table, UserTotpSecrets::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_table(Table::create()
            .table(TotpBackupCodes::Table).if_not_exists()
            .col(ColumnDef::new(TotpBackupCodes::Id).string().not_null().primary_key())
            .col(ColumnDef::new(TotpBackupCodes::UserId).string_len(36).not_null())
            .col(ColumnDef::new(TotpBackupCodes::CodeHash).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(TotpBackupCodes::Used).boolean().not_null().default(false))
            .col(ColumnDef::new(TotpBackupCodes::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(TotpBackupCodes::UsedAt).date_time().null())
            .foreign_key(ForeignKey::create().name("fk_backup_codes_user").from(TotpBackupCodes::Table, TotpBackupCodes::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_table(Table::create()
            .table(EmailVerificationTokens::Table).if_not_exists()
            .col(ColumnDef::new(EmailVerificationTokens::Id).string().not_null().primary_key())
            .col(ColumnDef::new(EmailVerificationTokens::UserId).string_len(36).not_null())
            .col(ColumnDef::new(EmailVerificationTokens::TokenHash).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(EmailVerificationTokens::ExpiresAt).date_time().not_null())
            .col(ColumnDef::new(EmailVerificationTokens::Used).boolean().not_null().default(false))
            .col(ColumnDef::new(EmailVerificationTokens::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_email_verification_tokens_user").from(EmailVerificationTokens::Table, EmailVerificationTokens::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        // ============================================================================
        // 4. PASSKEYS & WEBAUTHN
        // ============================================================================

        manager.create_table(Table::create()
            .table(UserPasskeys::Table).if_not_exists()
            .col(ColumnDef::new(UserPasskeys::Id).string().not_null().primary_key())
            .col(ColumnDef::new(UserPasskeys::UserId).string_len(36).not_null())
            .col(ColumnDef::new(UserPasskeys::CredentialId).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(UserPasskeys::PublicKey).text().not_null())
            .col(ColumnDef::new(UserPasskeys::Counter).big_integer().not_null().default(0))
            .col(ColumnDef::new(UserPasskeys::Aaguid).string().null())
            .col(ColumnDef::new(UserPasskeys::Name).string_len(100).not_null())
            .col(ColumnDef::new(UserPasskeys::BackupEligible).boolean().not_null().default(false))
            .col(ColumnDef::new(UserPasskeys::BackupState).boolean().not_null().default(false))
            .col(ColumnDef::new(UserPasskeys::Transports).string().null())
            .col(ColumnDef::new(UserPasskeys::LastUsedAt).date_time().null())
            .col(ColumnDef::new(UserPasskeys::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_user_passkeys_user").from(UserPasskeys::Table, UserPasskeys::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_user_passkeys_user").table(UserPasskeys::Table).col(UserPasskeys::UserId).to_owned()).await?;

        manager.create_table(Table::create()
            .table(WebauthnChallenges::Table).if_not_exists()
            .col(ColumnDef::new(WebauthnChallenges::Id).string().not_null().primary_key())
            .col(ColumnDef::new(WebauthnChallenges::UserId).string_len(36))
            .col(ColumnDef::new(WebauthnChallenges::ChallengeType).string())
            .col(ColumnDef::new(WebauthnChallenges::ChallengeState).text())
            .col(ColumnDef::new(WebauthnChallenges::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(WebauthnChallenges::ExpiresAt).date_time().not_null())
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_webauthn_challenges_expires").table(WebauthnChallenges::Table).col(WebauthnChallenges::ExpiresAt).to_owned()).await?;


        // PART 1 COMPLETE - Continue in next section
        Self::create_organization_tables(manager).await?;
        Self::create_service_tables(manager).await?;
        Self::create_system_tables(manager, backend).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse dependency order
        let tables = vec![
            DistributedLocks::Table.into_table_ref(),
            SystemJobs::Table.into_table_ref(),
            SiemConfigs::Table.into_table_ref(),
            RiskRules::Table.into_table_ref(),
            UserDevices::Table.into_table_ref(),
            Permissions::Table.into_table_ref(),
            WebhookDeliveries::Table.into_table_ref(),
            Webhooks::Table.into_table_ref(),
            OrganizationAuditLog::Table.into_table_ref(),
            MfaFeatureUsage::Table.into_table_ref(),
            MfaFailurePatterns::Table.into_table_ref(),
            MfaDailyMetrics::Table.into_table_ref(),
            MfaAuditLog::Table.into_table_ref(),
            LoginEvents::Table.into_table_ref(),
            StripeCustomers::Table.into_table_ref(),
            Subscriptions::Table.into_table_ref(),
            Plans::Table.into_table_ref(),
            ScimTokens::Table.into_table_ref(),
            SamlStates::Table.into_table_ref(),
            SamlSigningKeys::Table.into_table_ref(),
            ApiKeys::Table.into_table_ref(),
            VerifiedDomains::Table.into_table_ref(),
            UpstreamProviders::Table.into_table_ref(),
            Services::Table.into_table_ref(),
            OrganizationOauthCredentials::Table.into_table_ref(),
            OrganizationInvitations::Table.into_table_ref(),
            Memberships::Table.into_table_ref(),
            Organizations::Table.into_table_ref(),
            PlatformAuditLog::Table.into_table_ref(),
            OrganizationTiers::Table.into_table_ref(),
            WebauthnChallenges::Table.into_table_ref(),
            UserPasskeys::Table.into_table_ref(),
            EmailVerificationTokens::Table.into_table_ref(),
            TotpBackupCodes::Table.into_table_ref(),
            UserTotpSecrets::Table.into_table_ref(),
            PasswordResetTokens::Table.into_table_ref(),
            MagicLinkTokens::Table.into_table_ref(),
            TokenRefreshLocks::Table.into_table_ref(),
            OauthStates::Table.into_table_ref(),
            DeviceCodes::Table.into_table_ref(),
            Sessions::Table.into_table_ref(),
            Identities::Table.into_table_ref(),
            Users::Table.into_table_ref(),
        ];

        for table in tables {
            manager.drop_table(Table::drop().table(table).if_exists().to_owned()).await?;
        }

        Ok(())
    }
}

impl Migration {
    async fn create_organization_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Organization Tiers
        manager.create_table(Table::create()
            .table(OrganizationTiers::Table).if_not_exists()
            .col(ColumnDef::new(OrganizationTiers::Id).string().not_null().primary_key())
            .col(ColumnDef::new(OrganizationTiers::Name).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(OrganizationTiers::DisplayName).string_len(100).not_null())
            .col(ColumnDef::new(OrganizationTiers::DefaultMaxServices).integer().not_null().default(2))
            .col(ColumnDef::new(OrganizationTiers::DefaultMaxUsers).integer().not_null().default(3))
            .col(ColumnDef::new(OrganizationTiers::Features).text())
            .col(ColumnDef::new(OrganizationTiers::PriceCents).integer().not_null().default(0))
            .col(ColumnDef::new(OrganizationTiers::Currency).string().not_null().default("usd"))
            .col(ColumnDef::new(OrganizationTiers::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .to_owned()
        ).await?;

        // Seed Tiers
        db.execute_unprepared(r#"
            INSERT INTO organization_tiers (id, name, display_name, default_max_services, default_max_users, price_cents, features, created_at) VALUES
                ('tier_free', 'free', 'Free Tier', 2, 3, 0, '{"allow_custom_domain": false, "allow_saml_idp": false, "allow_scim": false, "allow_siem": false, "allow_branding": false, "allow_passkeys": true, "allowed_social_providers": ["github"], "max_mau": 1000}', CURRENT_TIMESTAMP),
                ('tier_starter', 'starter', 'Starter Tier', 10, 10, 4900, '{"allow_custom_domain": false, "allow_saml_idp": false, "allow_scim": false, "allow_siem": false, "allow_branding": false, "allow_passkeys": true, "allowed_social_providers": ["github", "google"], "max_mau": 5000}', CURRENT_TIMESTAMP),
                ('tier_pro', 'pro', 'Pro Tier', 50, 50, 14900, '{"allow_custom_domain": true, "allow_saml_idp": true, "allow_scim": true, "allow_siem": false, "allow_branding": true, "allow_passkeys": true, "allowed_social_providers": ["github", "google", "microsoft"], "max_mau": 25000}', CURRENT_TIMESTAMP),
                ('tier_enterprise', 'enterprise', 'Enterprise Tier', 999999, 999999, 49900, '{"allow_custom_domain": true, "allow_saml_idp": true, "allow_scim": true, "allow_siem": true, "allow_branding": true, "allow_passkeys": true, "allowed_social_providers": ["github", "google", "microsoft", "oidc"], "max_mau": 1000000}', CURRENT_TIMESTAMP)
        "#).await?;

        // Platform Audit Log
        manager.create_table(Table::create()
            .table(PlatformAuditLog::Table).if_not_exists()
            .col(ColumnDef::new(PlatformAuditLog::Id).string().not_null().primary_key())
            .col(ColumnDef::new(PlatformAuditLog::PlatformOwnerId).string().not_null())
            .col(ColumnDef::new(PlatformAuditLog::Action).string().not_null())
            .col(ColumnDef::new(PlatformAuditLog::TargetType).string().not_null())
            .col(ColumnDef::new(PlatformAuditLog::TargetId).string().not_null())
            .col(ColumnDef::new(PlatformAuditLog::Metadata).text())
            .col(ColumnDef::new(PlatformAuditLog::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_platform_audit_owner").from(PlatformAuditLog::Table, PlatformAuditLog::PlatformOwnerId).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        // Organizations
        manager.create_table(Table::create()
            .table(Organizations::Table).if_not_exists()
            .col(ColumnDef::new(Organizations::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Organizations::Slug).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(Organizations::Name).string_len(100).not_null())
            .col(ColumnDef::new(Organizations::OwnerUserId).string_len(36).not_null())
            .col(ColumnDef::new(Organizations::Status).string_len(50).not_null().default("pending"))
            .col(ColumnDef::new(Organizations::TierId).string())
            .col(ColumnDef::new(Organizations::MaxServices).integer())
            .col(ColumnDef::new(Organizations::MaxUsers).integer())
            .col(ColumnDef::new(Organizations::ApprovedBy).string())
            .col(ColumnDef::new(Organizations::ApprovedAt).date_time().null())
            .col(ColumnDef::new(Organizations::RejectedBy).string())
            .col(ColumnDef::new(Organizations::RejectedAt).date_time().null())
            .col(ColumnDef::new(Organizations::RejectionReason).string())
            .col(ColumnDef::new(Organizations::SmtpHost).string())
            .col(ColumnDef::new(Organizations::SmtpPort).integer())
            .col(ColumnDef::new(Organizations::SmtpUsername).string())
            .col(ColumnDef::new(Organizations::SmtpPasswordEncrypted).blob())
            .col(ColumnDef::new(Organizations::SmtpFromEmail).string_len(254))
            .col(ColumnDef::new(Organizations::SmtpFromName).string_len(100))
            .col(ColumnDef::new(Organizations::SmtpEncryptionKeyId).string().default("default"))
            .col(ColumnDef::new(Organizations::CustomDomain).string_len(191).unique_key())
            .col(ColumnDef::new(Organizations::DomainVerified).boolean().not_null().default(false))
            .col(ColumnDef::new(Organizations::DomainVerificationToken).string())
            .col(ColumnDef::new(Organizations::BrandLogoUrl).text())
            .col(ColumnDef::new(Organizations::BrandPrimaryColor).string())
            .col(ColumnDef::new(Organizations::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(Organizations::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_organizations_owner").from(Organizations::Table, Organizations::OwnerUserId).to(Users::Table, Users::Id))
            .foreign_key(ForeignKey::create().name("fk_organizations_tier").from(Organizations::Table, Organizations::TierId).to(OrganizationTiers::Table, OrganizationTiers::Id))
            .foreign_key(ForeignKey::create().name("fk_organizations_approved_by").from(Organizations::Table, Organizations::ApprovedBy).to(Users::Table, Users::Id))
            .foreign_key(ForeignKey::create().name("fk_organizations_rejected_by").from(Organizations::Table, Organizations::RejectedBy).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_organizations_status").table(Organizations::Table).col(Organizations::Status).to_owned()).await?;

        // Memberships
        manager.create_table(Table::create()
            .table(Memberships::Table).if_not_exists()
            .col(ColumnDef::new(Memberships::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Memberships::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(Memberships::UserId).string_len(36).not_null())
            .col(ColumnDef::new(Memberships::Role).string().not_null().default("member"))
            .col(ColumnDef::new(Memberships::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_memberships_org").from(Memberships::Table, Memberships::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_memberships_user").from(Memberships::Table, Memberships::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_memberships_org_user_unique").table(Memberships::Table).col(Memberships::OrgId).col(Memberships::UserId).unique().to_owned()).await?;
        manager.create_index(Index::create().name("idx_memberships_user").table(Memberships::Table).col(Memberships::UserId).to_owned()).await?;

        // Organization Invitations
        manager.create_table(Table::create()
            .table(OrganizationInvitations::Table).if_not_exists()
            .col(ColumnDef::new(OrganizationInvitations::Id).string().not_null().primary_key())
            .col(ColumnDef::new(OrganizationInvitations::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(OrganizationInvitations::Email).string_len(254).not_null())
            .col(ColumnDef::new(OrganizationInvitations::Role).string().not_null().default("member"))
            .col(ColumnDef::new(OrganizationInvitations::InvitedBy).string().not_null())
            .col(ColumnDef::new(OrganizationInvitations::Status).string_len(50).not_null().default("pending"))
            .col(ColumnDef::new(OrganizationInvitations::Token).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(OrganizationInvitations::ExpiresAt).date_time().not_null())
            .col(ColumnDef::new(OrganizationInvitations::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_org_invitations_org").from(OrganizationInvitations::Table, OrganizationInvitations::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_org_invitations_inviter").from(OrganizationInvitations::Table, OrganizationInvitations::InvitedBy).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_org_invitations_org_email_status_unique").table(OrganizationInvitations::Table).col(OrganizationInvitations::OrgId).col(OrganizationInvitations::Email).col(OrganizationInvitations::Status).unique().to_owned()).await?;

        // Organization OAuth Credentials
        manager.create_table(Table::create()
            .table(OrganizationOauthCredentials::Table).if_not_exists()
            .col(ColumnDef::new(OrganizationOauthCredentials::Id).string().not_null().primary_key())
            .col(ColumnDef::new(OrganizationOauthCredentials::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(OrganizationOauthCredentials::Provider).string_len(100).not_null())
            .col(ColumnDef::new(OrganizationOauthCredentials::ClientId).string().not_null())
            .col(ColumnDef::new(OrganizationOauthCredentials::ClientSecretEncrypted).blob().not_null())
            .col(ColumnDef::new(OrganizationOauthCredentials::EncryptionKeyId).string().not_null())
            .col(ColumnDef::new(OrganizationOauthCredentials::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(OrganizationOauthCredentials::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_org_oauth_creds_org").from(OrganizationOauthCredentials::Table, OrganizationOauthCredentials::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_org_oauth_creds_org_provider_unique").table(OrganizationOauthCredentials::Table).col(OrganizationOauthCredentials::OrgId).col(OrganizationOauthCredentials::Provider).unique().to_owned()).await?;

        // Organization Audit Log
        manager.create_table(Table::create()
            .table(OrganizationAuditLog::Table).if_not_exists()
            .col(ColumnDef::new(OrganizationAuditLog::Id).string().not_null().primary_key())
            .col(ColumnDef::new(OrganizationAuditLog::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(OrganizationAuditLog::ActorUserId).string_len(36).not_null())
            .col(ColumnDef::new(OrganizationAuditLog::Action).string().not_null())
            .col(ColumnDef::new(OrganizationAuditLog::TargetType).string().not_null())
            .col(ColumnDef::new(OrganizationAuditLog::TargetId).string().not_null())
            .col(ColumnDef::new(OrganizationAuditLog::IpAddress).string_len(50))
            .col(ColumnDef::new(OrganizationAuditLog::UserAgent).string())
            .col(ColumnDef::new(OrganizationAuditLog::Success).boolean().not_null().default(true))
            .col(ColumnDef::new(OrganizationAuditLog::Details).text())
            .col(ColumnDef::new(OrganizationAuditLog::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_org_audit_org").from(OrganizationAuditLog::Table, OrganizationAuditLog::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_org_audit_actor").from(OrganizationAuditLog::Table, OrganizationAuditLog::ActorUserId).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        Ok(())
    }

    async fn create_service_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        // Services
        manager.create_table(Table::create()
            .table(Services::Table).if_not_exists()
            .col(ColumnDef::new(Services::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Services::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(Services::Slug).string_len(100).not_null())
            .col(ColumnDef::new(Services::Name).string_len(100).not_null())
            .col(ColumnDef::new(Services::ServiceType).string().not_null())
            .col(ColumnDef::new(Services::ClientId).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(Services::ClientSecretHash).string().not_null().default(""))
            .col(ColumnDef::new(Services::GithubScopes).text())
            .col(ColumnDef::new(Services::MicrosoftScopes).text())
            .col(ColumnDef::new(Services::GoogleScopes).text())
            .col(ColumnDef::new(Services::RedirectUris).text())
            .col(ColumnDef::new(Services::DeviceActivationUri).text())
            .col(ColumnDef::new(Services::SamlEnabled).boolean().not_null().default(false))
            .col(ColumnDef::new(Services::SamlEntityId).text())
            .col(ColumnDef::new(Services::SamlAcsUrl).text())
            .col(ColumnDef::new(Services::SamlSloUrl).text())
            .col(ColumnDef::new(Services::SamlNameIdFormat).string().default("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"))
            .col(ColumnDef::new(Services::SamlAttributeMapping).text())
            .col(ColumnDef::new(Services::SamlSignAssertions).boolean().not_null().default(true))
            .col(ColumnDef::new(Services::SamlSignResponse).boolean().not_null().default(true))
            .col(ColumnDef::new(Services::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_services_org").from(Services::Table, Services::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_services_org_slug_unique").table(Services::Table).col(Services::OrgId).col(Services::Slug).unique().to_owned()).await?;
        manager.create_index(Index::create().name("idx_services_client").table(Services::Table).col(Services::ClientId).to_owned()).await?;

        // Upstream Providers (Enterprise SSO)
        manager.create_table(Table::create()
            .table(UpstreamProviders::Table).if_not_exists()
            .col(ColumnDef::new(UpstreamProviders::Id).string().not_null().primary_key())
            .col(ColumnDef::new(UpstreamProviders::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(UpstreamProviders::ConnectionId).string_len(100).not_null())
            .col(ColumnDef::new(UpstreamProviders::Name).string_len(100).not_null())
            .col(ColumnDef::new(UpstreamProviders::ProviderType).string().not_null())
            .col(ColumnDef::new(UpstreamProviders::Issuer).string())
            .col(ColumnDef::new(UpstreamProviders::ClientId).string().not_null())
            .col(ColumnDef::new(UpstreamProviders::ClientSecretEncrypted).blob().not_null())
            .col(ColumnDef::new(UpstreamProviders::EncryptionKeyId).string().not_null().default("default"))
            .col(ColumnDef::new(UpstreamProviders::AuthorizationUrl).text())
            .col(ColumnDef::new(UpstreamProviders::TokenUrl).text())
            .col(ColumnDef::new(UpstreamProviders::UserinfoUrl).text())
            .col(ColumnDef::new(UpstreamProviders::DiscoveryUrl).text())
            .col(ColumnDef::new(UpstreamProviders::Scopes).text())
            .col(ColumnDef::new(UpstreamProviders::Metadata).text())
            .col(ColumnDef::new(UpstreamProviders::Enabled).boolean().not_null().default(true))
            .col(ColumnDef::new(UpstreamProviders::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(UpstreamProviders::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_upstream_providers_org").from(UpstreamProviders::Table, UpstreamProviders::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_upstream_providers_org_connection").table(UpstreamProviders::Table).col(UpstreamProviders::OrgId).col(UpstreamProviders::ConnectionId).unique().to_owned()).await?;

        // Verified Domains
        manager.create_table(Table::create()
            .table(VerifiedDomains::Table).if_not_exists()
            .col(ColumnDef::new(VerifiedDomains::Id).string().not_null().primary_key())
            .col(ColumnDef::new(VerifiedDomains::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(VerifiedDomains::Domain).string().not_null())
            .col(ColumnDef::new(VerifiedDomains::UpstreamProviderId).string())
            .col(ColumnDef::new(VerifiedDomains::VerificationToken).string().not_null())
            .col(ColumnDef::new(VerifiedDomains::Verified).boolean().not_null().default(false))
            .col(ColumnDef::new(VerifiedDomains::VerifiedAt).date_time().null())
            .col(ColumnDef::new(VerifiedDomains::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(VerifiedDomains::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_verified_domains_org").from(VerifiedDomains::Table, VerifiedDomains::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_verified_domains_provider").from(VerifiedDomains::Table, VerifiedDomains::UpstreamProviderId).to(UpstreamProviders::Table, UpstreamProviders::Id).on_delete(ForeignKeyAction::SetNull))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_verified_domains_domain").table(VerifiedDomains::Table).col(VerifiedDomains::Domain).unique().to_owned()).await?;
        manager.create_index(Index::create().name("idx_verified_domains_org").table(VerifiedDomains::Table).col(VerifiedDomains::OrgId).to_owned()).await?;

        // API Keys
        manager.create_table(Table::create()
            .table(ApiKeys::Table).if_not_exists()
            .col(ColumnDef::new(ApiKeys::Id).string().not_null().primary_key())
            .col(ColumnDef::new(ApiKeys::ServiceId).string_len(36).not_null())
            .col(ColumnDef::new(ApiKeys::Name).string_len(100).not_null())
            .col(ColumnDef::new(ApiKeys::Prefix).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(ApiKeys::KeyHash).string().not_null())
            .col(ColumnDef::new(ApiKeys::Permissions).string().not_null())
            .col(ColumnDef::new(ApiKeys::LastUsedAt).date_time().null())
            .col(ColumnDef::new(ApiKeys::ExpiresAt).date_time().null())
            .col(ColumnDef::new(ApiKeys::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(ApiKeys::CreatedBy).string().not_null())
            .foreign_key(ForeignKey::create().name("fk_api_keys_service").from(ApiKeys::Table, ApiKeys::ServiceId).to(Services::Table, Services::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_api_keys_creator").from(ApiKeys::Table, ApiKeys::CreatedBy).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        // SAML Signing Keys
        manager.create_table(Table::create()
            .table(SamlSigningKeys::Table).if_not_exists()
            .col(ColumnDef::new(SamlSigningKeys::Id).string().not_null().primary_key())
            .col(ColumnDef::new(SamlSigningKeys::ServiceId).string_len(36).not_null())
            .col(ColumnDef::new(SamlSigningKeys::PrivateKeyEncrypted).blob().not_null())
            .col(ColumnDef::new(SamlSigningKeys::PublicKey).text().not_null())
            .col(ColumnDef::new(SamlSigningKeys::EncryptionKeyId).string().not_null())
            .col(ColumnDef::new(SamlSigningKeys::ValidFrom).date_time().not_null())
            .col(ColumnDef::new(SamlSigningKeys::ValidUntil).date_time().not_null())
            .col(ColumnDef::new(SamlSigningKeys::IsActive).boolean().not_null().default(true))
            .col(ColumnDef::new(SamlSigningKeys::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_saml_keys_service").from(SamlSigningKeys::Table, SamlSigningKeys::ServiceId).to(Services::Table, Services::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        // Partial unique index for active SAML keys (only one active per service)
        if matches!(backend, sea_orm::DatabaseBackend::Sqlite | sea_orm::DatabaseBackend::Postgres) {
            db.execute_unprepared("CREATE UNIQUE INDEX IF NOT EXISTS idx_saml_keys_service_active_unique ON saml_signing_keys(service_id) WHERE is_active = TRUE").await?;
        }

        // SAML States
        manager.create_table(Table::create()
            .table(SamlStates::Table).if_not_exists()
            .col(ColumnDef::new(SamlStates::StateId).string().not_null().primary_key())
            .col(ColumnDef::new(SamlStates::ServiceId).string_len(36).not_null())
            .col(ColumnDef::new(SamlStates::SamlRequest).text().not_null())
            .col(ColumnDef::new(SamlStates::RelayState).string())
            .col(ColumnDef::new(SamlStates::AcsUrl).string().not_null())
            .col(ColumnDef::new(SamlStates::RequestId).string())
            .col(ColumnDef::new(SamlStates::Issuer).string())
            .col(ColumnDef::new(SamlStates::Binding).string())
            .col(ColumnDef::new(SamlStates::UserId).string_len(36))
            .col(ColumnDef::new(SamlStates::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(SamlStates::ExpiresAt).date_time().not_null())
            .foreign_key(ForeignKey::create().name("fk_saml_states_service").from(SamlStates::Table, SamlStates::ServiceId).to(Services::Table, Services::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_saml_states_user").from(SamlStates::Table, SamlStates::UserId).to(Users::Table, Users::Id))
            .to_owned()
        ).await?;

        // SCIM Tokens
        manager.create_table(Table::create()
            .table(ScimTokens::Table).if_not_exists()
            .col(ColumnDef::new(ScimTokens::Id).string().not_null().primary_key())
            .col(ColumnDef::new(ScimTokens::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(ScimTokens::Name).string_len(100).not_null())
            .col(ColumnDef::new(ScimTokens::TokenHash).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(ScimTokens::Prefix).string().not_null())
            .col(ColumnDef::new(ScimTokens::Active).boolean().not_null().default(true))
            .col(ColumnDef::new(ScimTokens::ExpiresAt).date_time().null())
            .col(ColumnDef::new(ScimTokens::LastUsedAt).date_time().null())
            .col(ColumnDef::new(ScimTokens::CreatedBy).string().not_null())
            .col(ColumnDef::new(ScimTokens::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_scim_tokens_org").from(ScimTokens::Table, ScimTokens::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_scim_tokens_creator").from(ScimTokens::Table, ScimTokens::CreatedBy).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        // Plans
        manager.create_table(Table::create()
            .table(Plans::Table).if_not_exists()
            .col(ColumnDef::new(Plans::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Plans::ServiceId).string_len(36).not_null())
            .col(ColumnDef::new(Plans::Name).string_len(100).not_null())
            .col(ColumnDef::new(Plans::PriceCents).integer().not_null())
            .col(ColumnDef::new(Plans::Currency).string().not_null().default("usd"))
            .col(ColumnDef::new(Plans::Features).string())
            .col(ColumnDef::new(Plans::StripePriceId).string())
            .col(ColumnDef::new(Plans::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_plans_service").from(Plans::Table, Plans::ServiceId).to(Services::Table, Services::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_plans_service_name_unique").table(Plans::Table).col(Plans::ServiceId).col(Plans::Name).unique().to_owned()).await?;

        // Subscriptions
        manager.create_table(Table::create()
            .table(Subscriptions::Table).if_not_exists()
            .col(ColumnDef::new(Subscriptions::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Subscriptions::UserId).string_len(36).not_null())
            .col(ColumnDef::new(Subscriptions::ServiceId).string_len(36).not_null())
            .col(ColumnDef::new(Subscriptions::PlanId).string().not_null())
            .col(ColumnDef::new(Subscriptions::Status).string_len(50).not_null().default("active"))
            .col(ColumnDef::new(Subscriptions::CurrentPeriodEnd).date_time().not_null())
            .col(ColumnDef::new(Subscriptions::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_subscriptions_user").from(Subscriptions::Table, Subscriptions::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_subscriptions_service").from(Subscriptions::Table, Subscriptions::ServiceId).to(Services::Table, Services::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_subscriptions_plan").from(Subscriptions::Table, Subscriptions::PlanId).to(Plans::Table, Plans::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_subscriptions_user_service_unique").table(Subscriptions::Table).col(Subscriptions::UserId).col(Subscriptions::ServiceId).unique().to_owned()).await?;

        // Stripe Customers
        manager.create_table(Table::create()
            .table(StripeCustomers::Table).if_not_exists()
            .col(ColumnDef::new(StripeCustomers::Id).string().not_null().primary_key())
            .col(ColumnDef::new(StripeCustomers::OrgId).string_len(36).not_null().unique_key())
            .col(ColumnDef::new(StripeCustomers::StripeCustomerId).string_len(191).not_null().unique_key())
            .foreign_key(ForeignKey::create().name("fk_stripe_customers_org").from(StripeCustomers::Table, StripeCustomers::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        // Webhooks
        manager.create_table(Table::create()
            .table(Webhooks::Table).if_not_exists()
            .col(ColumnDef::new(Webhooks::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Webhooks::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(Webhooks::Name).string_len(100).not_null())
            .col(ColumnDef::new(Webhooks::Url).string().not_null())
            .col(ColumnDef::new(Webhooks::Secret).string().not_null())
            .col(ColumnDef::new(Webhooks::Events).string().not_null())
            .col(ColumnDef::new(Webhooks::IsActive).boolean().not_null().default(true))
            .col(ColumnDef::new(Webhooks::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(Webhooks::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_webhooks_org").from(Webhooks::Table, Webhooks::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_webhooks_org_name_unique").table(Webhooks::Table).col(Webhooks::OrgId).col(Webhooks::Name).unique().to_owned()).await?;

        // Webhook Deliveries
        manager.create_table(Table::create()
            .table(WebhookDeliveries::Table).if_not_exists()
            .col(ColumnDef::new(WebhookDeliveries::Id).string().not_null().primary_key())
            .col(ColumnDef::new(WebhookDeliveries::WebhookId).string().not_null())
            .col(ColumnDef::new(WebhookDeliveries::EventType).string().not_null())
            .col(ColumnDef::new(WebhookDeliveries::Payload).text().not_null())
            .col(ColumnDef::new(WebhookDeliveries::ResponseStatusCode).integer())
            .col(ColumnDef::new(WebhookDeliveries::ResponseBody).string())
            .col(ColumnDef::new(WebhookDeliveries::AttemptCount).integer().not_null().default(1))
            .col(ColumnDef::new(WebhookDeliveries::MaxAttempts).integer().not_null().default(5))
            .col(ColumnDef::new(WebhookDeliveries::NextRetryAt).date_time().null())
            .col(ColumnDef::new(WebhookDeliveries::Delivered).boolean().not_null().default(false))
            .col(ColumnDef::new(WebhookDeliveries::DeliveryError).string())
            .col(ColumnDef::new(WebhookDeliveries::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(WebhookDeliveries::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_webhook_deliveries_webhook").from(WebhookDeliveries::Table, WebhookDeliveries::WebhookId).to(Webhooks::Table, Webhooks::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        Ok(())
    }

    async fn create_system_tables(manager: &SchemaManager<'_>, backend: sea_orm::DatabaseBackend) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Login Events
        manager.create_table(Table::create()
            .table(LoginEvents::Table).if_not_exists()
            .col(ColumnDef::new(LoginEvents::Id).string().not_null().primary_key())
            .col(ColumnDef::new(LoginEvents::UserId).string_len(36).not_null())
            .col(ColumnDef::new(LoginEvents::ServiceId).string_len(36).null())
            .col(ColumnDef::new(LoginEvents::Provider).string_len(100).not_null())
            .col(ColumnDef::new(LoginEvents::IpAddress).string_len(50))
            .col(ColumnDef::new(LoginEvents::UserAgent).string())
            .col(ColumnDef::new(LoginEvents::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(LoginEvents::RiskScore).integer().null())
            .col(ColumnDef::new(LoginEvents::RiskFactors).string().null())
            .col(ColumnDef::new(LoginEvents::GeoCountry).string().null())
            .col(ColumnDef::new(LoginEvents::GeoCity).string().null())
            .col(ColumnDef::new(LoginEvents::GeoLat).double().null())
            .col(ColumnDef::new(LoginEvents::GeoLong).double().null())
            .foreign_key(ForeignKey::create().name("fk_login_events_user").from(LoginEvents::Table, LoginEvents::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_login_events_service").from(LoginEvents::Table, LoginEvents::ServiceId).to(Services::Table, Services::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_login_events_created").table(LoginEvents::Table).col(LoginEvents::CreatedAt).to_owned()).await?;

        // MFA Audit Log - Tracks MFA events per user (org_id denormalized for efficient multi-tenant queries)
        manager.create_table(Table::create()
            .table(MfaAuditLog::Table).if_not_exists()
            .col(ColumnDef::new(MfaAuditLog::Id).string().not_null().primary_key())
            .col(ColumnDef::new(MfaAuditLog::OrgId).string_len(36)) // nullable: NULL = platform-level MFA (no org context)
            .col(ColumnDef::new(MfaAuditLog::UserId).string_len(36).not_null())
            .col(ColumnDef::new(MfaAuditLog::EventType).string().not_null())
            .col(ColumnDef::new(MfaAuditLog::IpAddress).string_len(50))
            .col(ColumnDef::new(MfaAuditLog::UserAgent).string())
            .col(ColumnDef::new(MfaAuditLog::Success).boolean().not_null())
            .col(ColumnDef::new(MfaAuditLog::Details).text())
            .col(ColumnDef::new(MfaAuditLog::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            // Note: No FK to organizations - org_id is nullable and may not reference a valid org (platform-level events)
            .foreign_key(ForeignKey::create().name("fk_mfa_audit_user").from(MfaAuditLog::Table, MfaAuditLog::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_mfa_audit_org_created").table(MfaAuditLog::Table).col(MfaAuditLog::OrgId).col(MfaAuditLog::CreatedAt).to_owned()).await?;
        manager.create_index(Index::create().name("idx_mfa_audit_user_created").table(MfaAuditLog::Table).col(MfaAuditLog::UserId).col(MfaAuditLog::CreatedAt).to_owned()).await?;

        // MFA Daily Metrics - Aggregated by org and date (org_id nullable for platform-wide rollups)
        manager.create_table(Table::create()
            .table(MfaDailyMetrics::Table).if_not_exists()
            .col(ColumnDef::new(MfaDailyMetrics::Id).string().not_null().primary_key())
            .col(ColumnDef::new(MfaDailyMetrics::OrgId).string_len(36)) // NULL = platform-wide
            .col(ColumnDef::new(MfaDailyMetrics::Date).string_len(20).not_null())
            .col(ColumnDef::new(MfaDailyMetrics::TotalUsers).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::MfaEnabledUsers).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::NewMfaSetups).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::MfaDisabled).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::TotpVerificationsTotal).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::TotpVerificationsSuccess).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::TotpVerificationsFailed).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::BackupCodesGenerated).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::BackupCodesUsed).integer().not_null().default(0))
            .col(ColumnDef::new(MfaDailyMetrics::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(MfaDailyMetrics::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_mfa_metrics_org").from(MfaDailyMetrics::Table, MfaDailyMetrics::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_mfa_metrics_org_date").table(MfaDailyMetrics::Table).col(MfaDailyMetrics::OrgId).col(MfaDailyMetrics::Date).unique().to_owned()).await?;

        // MFA Failure Patterns - Tracks suspicious MFA activity per user/IP (org_id for multi-tenant visibility)
        manager.create_table(Table::create()
            .table(MfaFailurePatterns::Table).if_not_exists()
            .col(ColumnDef::new(MfaFailurePatterns::Id).string().not_null().primary_key())
            .col(ColumnDef::new(MfaFailurePatterns::OrgId).string_len(36)) // nullable: IP-only patterns may not have org
            .col(ColumnDef::new(MfaFailurePatterns::UserId).string_len(36))
            .col(ColumnDef::new(MfaFailurePatterns::IpAddress).string_len(50))
            .col(ColumnDef::new(MfaFailurePatterns::FailureType).string().not_null())
            .col(ColumnDef::new(MfaFailurePatterns::FailureCount).integer().not_null().default(0))
            .col(ColumnDef::new(MfaFailurePatterns::FirstSeenAt).date_time().not_null())
            .col(ColumnDef::new(MfaFailurePatterns::LastSeenAt).date_time().not_null())
            .col(ColumnDef::new(MfaFailurePatterns::IsSuspicious).boolean().not_null().default(false))
            .col(ColumnDef::new(MfaFailurePatterns::Details).text())
            .foreign_key(ForeignKey::create().name("fk_mfa_failures_org").from(MfaFailurePatterns::Table, MfaFailurePatterns::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_mfa_failures_user").from(MfaFailurePatterns::Table, MfaFailurePatterns::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::SetNull))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_mfa_failures_org").table(MfaFailurePatterns::Table).col(MfaFailurePatterns::OrgId).to_owned()).await?;
        manager.create_index(Index::create().name("idx_mfa_failures_user_ip").table(MfaFailurePatterns::Table).col(MfaFailurePatterns::UserId).col(MfaFailurePatterns::IpAddress).to_owned()).await?;

        // MFA Feature Usage - Tracks per-user MFA feature usage events (org_id for multi-tenant visibility)
        manager.create_table(Table::create()
            .table(MfaFeatureUsage::Table).if_not_exists()
            .col(ColumnDef::new(MfaFeatureUsage::Id).string().not_null().primary_key())
            .col(ColumnDef::new(MfaFeatureUsage::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(MfaFeatureUsage::UserId).string_len(36).not_null())
            .col(ColumnDef::new(MfaFeatureUsage::FeatureType).string().not_null())
            .col(ColumnDef::new(MfaFeatureUsage::Timestamp).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(MfaFeatureUsage::IpAddress).string_len(50))
            .col(ColumnDef::new(MfaFeatureUsage::UserAgent).string())
            .col(ColumnDef::new(MfaFeatureUsage::Success).boolean().not_null())
            .col(ColumnDef::new(MfaFeatureUsage::Details).text())
            .foreign_key(ForeignKey::create().name("fk_mfa_feature_usage_org").from(MfaFeatureUsage::Table, MfaFeatureUsage::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .foreign_key(ForeignKey::create().name("fk_mfa_feature_usage_user").from(MfaFeatureUsage::Table, MfaFeatureUsage::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_mfa_feature_usage_org").table(MfaFeatureUsage::Table).col(MfaFeatureUsage::OrgId).to_owned()).await?;
        manager.create_index(Index::create().name("idx_mfa_feature_usage_user").table(MfaFeatureUsage::Table).col(MfaFeatureUsage::UserId).to_owned()).await?;


        // Permissions (ReBAC)
        manager.create_table(Table::create()
            .table(Permissions::Table).if_not_exists()
            .col(ColumnDef::new(Permissions::Id).string().not_null().primary_key())
            .col(ColumnDef::new(Permissions::Namespace).string_len(100).not_null())
            .col(ColumnDef::new(Permissions::ObjectId).string_len(36).not_null())
            .col(ColumnDef::new(Permissions::Relation).string_len(100).not_null())
            .col(ColumnDef::new(Permissions::SubjectType).string_len(100).not_null())
            .col(ColumnDef::new(Permissions::SubjectId).string_len(36).not_null())
            .col(ColumnDef::new(Permissions::SubjectRelation).string_len(100).null())
            .col(ColumnDef::new(Permissions::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_permissions_check").table(Permissions::Table).col(Permissions::Namespace).col(Permissions::ObjectId).col(Permissions::Relation).col(Permissions::SubjectType).col(Permissions::SubjectId).to_owned()).await?;
        manager.create_index(Index::create().name("idx_permissions_expand").table(Permissions::Table).col(Permissions::Namespace).col(Permissions::ObjectId).col(Permissions::Relation).to_owned()).await?;
        manager.create_index(Index::create().name("idx_permissions_unique_tuple").table(Permissions::Table).col(Permissions::Namespace).col(Permissions::ObjectId).col(Permissions::Relation).col(Permissions::SubjectType).col(Permissions::SubjectId).col(Permissions::SubjectRelation).unique().to_owned()).await?;

        // User Devices (Risk Engine)
        manager.create_table(Table::create()
            .table(UserDevices::Table).if_not_exists()
            .col(ColumnDef::new(UserDevices::Id).string().not_null().primary_key())
            .col(ColumnDef::new(UserDevices::UserId).string_len(36).not_null())
            .col(ColumnDef::new(UserDevices::TrustTokenHash).string_len(191).not_null().unique_key())
            .col(ColumnDef::new(UserDevices::Name).string_len(100).not_null())
            .col(ColumnDef::new(UserDevices::LastIp).string().null())
            .col(ColumnDef::new(UserDevices::LastSeenAt).date_time().not_null())
            .col(ColumnDef::new(UserDevices::ExpiresAt).date_time().not_null())
            .col(ColumnDef::new(UserDevices::IsTrusted).boolean().not_null().default(true))
            .col(ColumnDef::new(UserDevices::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_user_devices_user").from(UserDevices::Table, UserDevices::UserId).to(Users::Table, Users::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_user_devices_user").table(UserDevices::Table).col(UserDevices::UserId).to_owned()).await?;

        // Risk Rules
        manager.create_table(Table::create()
            .table(RiskRules::Table).if_not_exists()
            .col(ColumnDef::new(RiskRules::Id).string().not_null().primary_key())
            .col(ColumnDef::new(RiskRules::OrgId).string_len(36).not_null().unique_key())
            .col(ColumnDef::new(RiskRules::EnforcementMode).string().not_null().default("log_only"))
            .col(ColumnDef::new(RiskRules::LowThreshold).integer().not_null().default(30))
            .col(ColumnDef::new(RiskRules::MediumThreshold).integer().not_null().default(70))
            .col(ColumnDef::new(RiskRules::NewDeviceScore).integer().not_null().default(20))
            .col(ColumnDef::new(RiskRules::ImpossibleTravelScore).integer().not_null().default(50))
            .col(ColumnDef::new(RiskRules::VelocityThreshold).integer().not_null().default(10))
            .col(ColumnDef::new(RiskRules::VelocityScore).integer().not_null().default(30))
            .col(ColumnDef::new(RiskRules::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(RiskRules::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_risk_rules_org").from(RiskRules::Table, RiskRules::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        // SIEM Configs
        manager.create_table(Table::create()
            .table(SiemConfigs::Table).if_not_exists()
            .col(ColumnDef::new(SiemConfigs::Id).string().not_null().primary_key())
            .col(ColumnDef::new(SiemConfigs::OrgId).string_len(36).not_null())
            .col(ColumnDef::new(SiemConfigs::Name).string_len(100).not_null())
            .col(ColumnDef::new(SiemConfigs::Provider).string_len(100).not_null())
            .col(ColumnDef::new(SiemConfigs::EndpointUrl).string().not_null())
            .col(ColumnDef::new(SiemConfigs::ApiKey).string().null())
            .col(ColumnDef::new(SiemConfigs::AuthHeader).string().null())
            .col(ColumnDef::new(SiemConfigs::BatchSize).string().not_null().default("100"))
            .col(ColumnDef::new(SiemConfigs::Enabled).boolean().not_null().default(true))
            .col(ColumnDef::new(SiemConfigs::LastSuccessfulBatchAt).date_time().null())
            .col(ColumnDef::new(SiemConfigs::LastProcessedLogId).string().null())
            .col(ColumnDef::new(SiemConfigs::FailureCount).integer().not_null().default(0))
            .col(ColumnDef::new(SiemConfigs::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(SiemConfigs::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .foreign_key(ForeignKey::create().name("fk_siem_configs_org").from(SiemConfigs::Table, SiemConfigs::OrgId).to(Organizations::Table, Organizations::Id).on_delete(ForeignKeyAction::Cascade))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_siem_configs_last_log").table(SiemConfigs::Table).col(SiemConfigs::LastProcessedLogId).to_owned()).await?;

        // System Jobs
        manager.create_table(Table::create()
            .table(SystemJobs::Table).if_not_exists()
            .col(ColumnDef::new(SystemJobs::Id).string().not_null().primary_key())
            .col(ColumnDef::new(SystemJobs::JobType).string().not_null())
            .col(ColumnDef::new(SystemJobs::Payload).text().not_null())
            .col(ColumnDef::new(SystemJobs::Status).string_len(50).not_null())
            .col(ColumnDef::new(SystemJobs::Priority).integer().not_null().default(0))
            .col(ColumnDef::new(SystemJobs::MaxRetries).integer().not_null().default(3))
            .col(ColumnDef::new(SystemJobs::AttemptCount).integer().not_null().default(0))
            .col(ColumnDef::new(SystemJobs::ScheduledFor).date_time().not_null())
            .col(ColumnDef::new(SystemJobs::LastAttemptAt).date_time().null())
            .col(ColumnDef::new(SystemJobs::CompletedAt).date_time().null())
            .col(ColumnDef::new(SystemJobs::FailedAt).date_time().null())
            .col(ColumnDef::new(SystemJobs::ErrorMessage).text().null())
            .col(ColumnDef::new(SystemJobs::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .col(ColumnDef::new(SystemJobs::UpdatedAt).date_time().not_null().default(Expr::current_timestamp()))
            .to_owned()
        ).await?;

        manager.create_index(Index::create().name("idx_system_jobs_poll").table(SystemJobs::Table).col(SystemJobs::Status).col(SystemJobs::ScheduledFor).col(SystemJobs::Priority).to_owned()).await?;

        // Distributed Locks (SQLite-only, PostgreSQL uses advisory locks)
        if backend == sea_orm::DatabaseBackend::Sqlite {
            manager.create_table(Table::create()
                .table(DistributedLocks::Table).if_not_exists()
                .col(ColumnDef::new(DistributedLocks::LockKey).string().not_null().primary_key())
                .col(ColumnDef::new(DistributedLocks::OwnerId).string().not_null())
                .col(ColumnDef::new(DistributedLocks::AcquiredAt).date_time().not_null())
                .col(ColumnDef::new(DistributedLocks::ExpiresAt).date_time().not_null())
                .to_owned()
            ).await?;
        }

        let _ = db;
        Ok(())
    }
}

// ============================================================================
// IDEN DEFINITIONS
// ============================================================================

#[derive(DeriveIden)]
enum Users { Table, Id, Email, IsPlatformOwner, PasswordHash, EmailVerifiedAt, CreatedAt, UpdatedAt, DeletedAt }

#[derive(DeriveIden)]
enum Identities { Table, Id, UserId, Provider, ProviderUserId, AccessToken, RefreshToken, AccessTokenEncrypted, RefreshTokenEncrypted, EncryptionKeyId, ExpiresAt, Scopes, LastRefreshedAt, IssuingOrgId, IssuingServiceId, CreatedAt }

#[derive(DeriveIden)]
enum Sessions { Table, Id, UserId, TokenHash, ExpiresAt, RefreshToken, RefreshTokenExpiresAt, OrgSlug, ServiceId, UserAgent, IpAddress, CreatedAt }

#[derive(DeriveIden)]
enum DeviceCodes { Table, Id, DeviceCode, UserCode, ClientId, OrgSlug, ServiceSlug, ExpiresAt, UserId, Status }

#[derive(DeriveIden)]
enum OauthStates { Table, State, PkceVerifier, ServiceId, RedirectUri, OrgSlug, ServiceSlug, IsAdminFlow, UserIdForLinking, DeviceUserCode, SamlStateId, CreatedAt, ExpiresAt }

#[derive(DeriveIden)]
enum TokenRefreshLocks { Table, UserId, AcquiredAt, ExpiresAt }

#[derive(DeriveIden)]
enum MagicLinkTokens { Table, TokenHash, UserId, Email, Context, CreatedAt, ExpiresAt }

#[derive(DeriveIden)]
enum PasswordResetTokens { Table, Id, UserId, TokenHash, ExpiresAt, Used, CreatedAt }

#[derive(DeriveIden)]
enum UserTotpSecrets { Table, Id, UserId, SecretEncrypted, EncryptionKeyId, Enabled, CreatedAt, EnabledAt }

#[derive(DeriveIden)]
enum TotpBackupCodes { Table, Id, UserId, CodeHash, Used, CreatedAt, UsedAt }

#[derive(DeriveIden)]
enum EmailVerificationTokens { Table, Id, UserId, TokenHash, ExpiresAt, Used, CreatedAt }

#[derive(DeriveIden)]
enum UserPasskeys { Table, Id, UserId, CredentialId, PublicKey, Counter, Aaguid, Name, BackupEligible, BackupState, Transports, LastUsedAt, CreatedAt }

#[derive(DeriveIden)]
enum WebauthnChallenges { Table, Id, UserId, ChallengeType, ChallengeState, CreatedAt, ExpiresAt }

#[derive(DeriveIden)]
enum OrganizationTiers { Table, Id, Name, DisplayName, DefaultMaxServices, DefaultMaxUsers, Features, PriceCents, Currency, CreatedAt }

#[derive(DeriveIden)]
enum PlatformAuditLog { Table, Id, PlatformOwnerId, Action, TargetType, TargetId, Metadata, CreatedAt }

#[derive(DeriveIden)]
enum Organizations { Table, Id, Slug, Name, OwnerUserId, Status, TierId, MaxServices, MaxUsers, ApprovedBy, ApprovedAt, RejectedBy, RejectedAt, RejectionReason, SmtpHost, SmtpPort, SmtpUsername, SmtpPasswordEncrypted, SmtpFromEmail, SmtpFromName, SmtpEncryptionKeyId, CustomDomain, DomainVerified, DomainVerificationToken, BrandLogoUrl, BrandPrimaryColor, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum Memberships { Table, Id, OrgId, UserId, Role, CreatedAt }

#[derive(DeriveIden)]
enum OrganizationInvitations { Table, Id, OrgId, Email, Role, InvitedBy, Status, Token, ExpiresAt, CreatedAt }

#[derive(DeriveIden)]
enum OrganizationOauthCredentials { Table, Id, OrgId, Provider, ClientId, ClientSecretEncrypted, EncryptionKeyId, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum OrganizationAuditLog { Table, Id, OrgId, ActorUserId, Action, TargetType, TargetId, IpAddress, UserAgent, Success, Details, CreatedAt }

#[derive(DeriveIden)]
enum Services { Table, Id, OrgId, Slug, Name, ServiceType, ClientId, ClientSecretHash, GithubScopes, MicrosoftScopes, GoogleScopes, RedirectUris, DeviceActivationUri, SamlEnabled, SamlEntityId, SamlAcsUrl, SamlSloUrl, SamlNameIdFormat, SamlAttributeMapping, SamlSignAssertions, SamlSignResponse, CreatedAt }

#[derive(DeriveIden)]
enum UpstreamProviders { Table, Id, OrgId, ConnectionId, Name, ProviderType, Issuer, ClientId, ClientSecretEncrypted, EncryptionKeyId, AuthorizationUrl, TokenUrl, UserinfoUrl, DiscoveryUrl, Scopes, Metadata, Enabled, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum VerifiedDomains { Table, Id, OrgId, Domain, UpstreamProviderId, VerificationToken, Verified, VerifiedAt, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum ApiKeys { Table, Id, ServiceId, Name, Prefix, KeyHash, Permissions, LastUsedAt, ExpiresAt, CreatedAt, CreatedBy }

#[derive(DeriveIden)]
enum SamlSigningKeys { Table, Id, ServiceId, PrivateKeyEncrypted, PublicKey, EncryptionKeyId, ValidFrom, ValidUntil, IsActive, CreatedAt }

#[derive(DeriveIden)]
enum SamlStates { Table, StateId, ServiceId, SamlRequest, RelayState, AcsUrl, RequestId, Issuer, Binding, UserId, CreatedAt, ExpiresAt }

#[derive(DeriveIden)]
enum ScimTokens { Table, Id, OrgId, Name, TokenHash, Prefix, Active, ExpiresAt, LastUsedAt, CreatedBy, CreatedAt }

#[derive(DeriveIden)]
enum Plans { Table, Id, ServiceId, Name, PriceCents, Currency, Features, StripePriceId, CreatedAt }

#[derive(DeriveIden)]
enum Subscriptions { Table, Id, UserId, ServiceId, PlanId, Status, CurrentPeriodEnd, CreatedAt }

#[derive(DeriveIden)]
enum StripeCustomers { Table, Id, OrgId, StripeCustomerId }

#[derive(DeriveIden)]
enum Webhooks { Table, Id, OrgId, Name, Url, Secret, Events, IsActive, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum WebhookDeliveries { Table, Id, WebhookId, EventType, Payload, ResponseStatusCode, ResponseBody, AttemptCount, MaxAttempts, NextRetryAt, Delivered, DeliveryError, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum LoginEvents { Table, Id, UserId, ServiceId, Provider, IpAddress, UserAgent, CreatedAt, RiskScore, RiskFactors, GeoCountry, GeoCity, GeoLat, GeoLong }

#[derive(DeriveIden)]
enum MfaAuditLog { Table, Id, OrgId, UserId, EventType, IpAddress, UserAgent, Success, Details, CreatedAt }

#[derive(DeriveIden)]
enum MfaDailyMetrics { Table, Id, OrgId, Date, TotalUsers, MfaEnabledUsers, NewMfaSetups, MfaDisabled, TotpVerificationsTotal, TotpVerificationsSuccess, TotpVerificationsFailed, BackupCodesGenerated, BackupCodesUsed, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum MfaFailurePatterns { Table, Id, OrgId, UserId, IpAddress, FailureType, FailureCount, FirstSeenAt, LastSeenAt, IsSuspicious, Details }

#[derive(DeriveIden)]
enum MfaFeatureUsage { Table, Id, OrgId, UserId, FeatureType, Timestamp, IpAddress, UserAgent, Success, Details }


#[derive(DeriveIden)]
enum Permissions { Table, Id, Namespace, ObjectId, Relation, SubjectType, SubjectId, SubjectRelation, CreatedAt }

#[derive(DeriveIden)]
enum UserDevices { Table, Id, UserId, TrustTokenHash, Name, LastIp, LastSeenAt, ExpiresAt, IsTrusted, CreatedAt }

#[derive(DeriveIden)]
enum RiskRules { Table, Id, OrgId, EnforcementMode, LowThreshold, MediumThreshold, NewDeviceScore, ImpossibleTravelScore, VelocityThreshold, VelocityScore, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum SiemConfigs { Table, Id, OrgId, Name, Provider, EndpointUrl, ApiKey, AuthHeader, BatchSize, Enabled, LastSuccessfulBatchAt, LastProcessedLogId, FailureCount, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum SystemJobs { Table, Id, JobType, Payload, Status, Priority, MaxRetries, AttemptCount, ScheduledFor, LastAttemptAt, CompletedAt, FailedAt, ErrorMessage, CreatedAt, UpdatedAt }

#[derive(DeriveIden)]
enum DistributedLocks { Table, LockKey, OwnerId, AcquiredAt, ExpiresAt }
