-- ============================================================================
-- PLATFORM SSO - UNIFIED INITIAL SCHEMA
-- Complete multi-tenant B2B2C platform with governance
-- ============================================================================

-- ----------------------------------------------------------------------------
-- USERS & AUTHENTICATION
-- ----------------------------------------------------------------------------

-- Global users (SSO-authenticated)
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    is_platform_owner BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SSO identities (GitHub, Google, Microsoft)
CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    -- Token storage (plaintext, will be NULL if encrypted)
    access_token TEXT,
    refresh_token TEXT,
    -- Encrypted token storage (BLOB, used when encryption enabled)
    access_token_encrypted BLOB,
    refresh_token_encrypted BLOB,
    encryption_key_id TEXT DEFAULT 'default',
    -- Token metadata
    expires_at DATETIME,
    scopes TEXT, -- JSON array of scopes
    last_refreshed_at DATETIME,
    UNIQUE(user_id, provider),
    UNIQUE(provider, provider_user_id)
);

-- Session tracking for JWT revocation
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL
);

-- OAuth device flow (for CLIs and mobile apps)
CREATE TABLE device_codes (
    id TEXT PRIMARY KEY,
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    org_slug TEXT NOT NULL,
    service_slug TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    user_id TEXT REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending' -- 'pending', 'authorized'
);

-- OAuth state storage (PKCE for Microsoft + web redirect)
CREATE TABLE oauth_states (
    state TEXT PRIMARY KEY,
    pkce_verifier TEXT,
    service_id TEXT,
    redirect_uri TEXT,
    org_slug TEXT,
    service_slug TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

-- Token refresh locking (prevent concurrent refreshes)
CREATE TABLE token_refresh_locks (
    user_id TEXT PRIMARY KEY,
    acquired_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);

-- ----------------------------------------------------------------------------
-- PLATFORM GOVERNANCE
-- ----------------------------------------------------------------------------

-- Organization tiers (pricing/limit templates)
CREATE TABLE organization_tiers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    default_max_services INTEGER NOT NULL DEFAULT 2,
    default_max_users INTEGER NOT NULL DEFAULT 3,
    features TEXT, -- JSON: {"api_access": true, "sso_providers": ["github"]}
    price_cents INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'usd',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Platform audit log (compliance and tracking)
CREATE TABLE platform_audit_log (
    id TEXT PRIMARY KEY,
    platform_owner_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL, -- 'approve_org', 'reject_org', 'suspend_org', 'set_tier', etc.
    target_type TEXT NOT NULL, -- 'organization', 'user', 'service'
    target_id TEXT NOT NULL,
    metadata TEXT, -- JSON: {"old_status": "pending", "new_status": "active"}
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- ORGANIZATIONS & TEAMS
-- ----------------------------------------------------------------------------

-- Organizations (tenants, require platform approval)
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    -- Governance
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'active', 'suspended', 'rejected'
    tier_id TEXT REFERENCES organization_tiers(id),
    max_services INTEGER, -- NULL = use tier default, otherwise custom override
    max_users INTEGER, -- NULL = use tier default, otherwise custom override
    -- Approval tracking
    approved_by TEXT REFERENCES users(id),
    approved_at DATETIME,
    rejected_by TEXT REFERENCES users(id),
    rejected_at DATETIME,
    rejection_reason TEXT,
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Organization team memberships
CREATE TABLE memberships (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member', -- 'owner', 'admin', 'member'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, user_id)
);

-- Team invitations
CREATE TABLE organization_invitations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member', -- 'admin', 'member' (NOT 'owner')
    invited_by TEXT NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'accepted', 'rejected', 'cancelled'
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, email, status) -- One pending invite per email per org
);

-- ----------------------------------------------------------------------------
-- SERVICES & SUBSCRIPTIONS
-- ----------------------------------------------------------------------------

-- Services (OAuth2 clients owned by organizations)
CREATE TABLE services (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    service_type TEXT NOT NULL, -- 'web', 'mobile', 'desktop', 'api'
    client_id TEXT NOT NULL UNIQUE, -- OAuth2 client identifier
    -- OAuth scopes per provider (JSON arrays)
    github_scopes TEXT,
    microsoft_scopes TEXT,
    google_scopes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, slug)
);

-- Provider token grants (which providers can services access)
CREATE TABLE provider_token_grants (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, -- 'github', 'google', 'microsoft'
    required BOOLEAN NOT NULL DEFAULT 0, -- Is provider mandatory for service?
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(service_id, provider)
);

-- Pricing plans (for end-user subscriptions)
CREATE TABLE plans (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'usd',
    features TEXT, -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(service_id, name)
);

-- End-user subscriptions (to services)
CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active', -- 'active', 'cancelled', 'expired'
    current_period_end DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, service_id)
);

-- ----------------------------------------------------------------------------
-- BILLING
-- ----------------------------------------------------------------------------

-- Stripe customer mapping (1:1 with organizations)
CREATE TABLE stripe_customers (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_customer_id TEXT NOT NULL UNIQUE
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Users & Auth
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_identities_user ON identities(user_id);
CREATE INDEX idx_identities_provider_user ON identities(provider, provider_user_id);
CREATE INDEX idx_identities_expires_at ON identities(expires_at);
CREATE INDEX idx_identities_encryption_key ON identities(encryption_key_id);

-- Organizations & Teams
CREATE INDEX idx_organizations_status ON organizations(status);
CREATE INDEX idx_organizations_tier ON organizations(tier_id);
CREATE INDEX idx_organizations_owner ON organizations(owner_user_id);
CREATE INDEX idx_memberships_org_user ON memberships(org_id, user_id);
CREATE INDEX idx_memberships_user ON memberships(user_id);
CREATE INDEX idx_organization_invitations_org ON organization_invitations(org_id);
CREATE INDEX idx_organization_invitations_email ON organization_invitations(email);
CREATE INDEX idx_organization_invitations_token ON organization_invitations(token);
CREATE INDEX idx_organization_invitations_status ON organization_invitations(status);

-- Services & Subscriptions
CREATE INDEX idx_services_org_slug ON services(org_id, slug);
CREATE INDEX idx_services_client ON services(client_id);
CREATE INDEX idx_provider_token_grants_service ON provider_token_grants(service_id);
CREATE INDEX idx_plans_service ON plans(service_id);
CREATE INDEX idx_subscriptions_user_service ON subscriptions(user_id, service_id);
CREATE INDEX idx_subscriptions_service ON subscriptions(service_id);

-- Platform Governance
CREATE INDEX idx_platform_audit_log_owner ON platform_audit_log(platform_owner_id);
CREATE INDEX idx_platform_audit_log_target ON platform_audit_log(target_type, target_id);
CREATE INDEX idx_platform_audit_log_created ON platform_audit_log(created_at);

-- OAuth Flows
CREATE INDEX idx_oauth_states_expires_at ON oauth_states(expires_at);
CREATE INDEX idx_token_refresh_locks_expires_at ON token_refresh_locks(expires_at);

-- ============================================================================
-- SEED DATA
-- ============================================================================

-- Organization tiers
INSERT INTO organization_tiers (id, name, display_name, default_max_services, default_max_users, price_cents, features) VALUES
    ('tier_free', 'free', 'Free Tier', 2, 3, 0, '{"sso_providers": ["github"], "api_access": false, "support": "community"}'),
    ('tier_starter', 'starter', 'Starter Tier', 10, 10, 4900, '{"sso_providers": ["github", "google"], "api_access": true, "support": "email"}'),
    ('tier_pro', 'pro', 'Pro Tier', 50, 50, 14900, '{"sso_providers": ["github", "google", "microsoft"], "api_access": true, "custom_domains": true, "support": "priority"}'),
    ('tier_enterprise', 'enterprise', 'Enterprise Tier', 999999, 999999, 49900, '{"sso_providers": ["github", "google", "microsoft"], "api_access": true, "custom_domains": true, "sla": true, "support": "dedicated"}');
