-- Fix identity isolation by removing global uniqueness constraint
-- This allows the same external OAuth identity (e.g., Bob's GitHub) to be used
-- across multiple contexts (platform admin + service end-user)
-- while maintaining proper isolation within each context

-- Temporarily disable foreign keys
PRAGMA foreign_keys=OFF;

-- Create new identities table WITHOUT the global UNIQUE(provider, provider_user_id) constraint
CREATE TABLE identities_new (
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
    scopes TEXT,
    last_refreshed_at DATETIME,
    -- Isolation columns
    issuing_org_id TEXT REFERENCES organizations(id),
    issuing_service_id TEXT REFERENCES services(id)
    -- NOTE: Removed global UNIQUE(provider, provider_user_id) to allow multi-context usage
);

-- Copy all data to new table
INSERT INTO identities_new
SELECT id, user_id, provider, provider_user_id, access_token, refresh_token,
       access_token_encrypted, refresh_token_encrypted, encryption_key_id,
       expires_at, scopes, last_refreshed_at, issuing_org_id, issuing_service_id
FROM identities;

-- Drop old table
DROP TABLE identities;

-- Rename new table
ALTER TABLE identities_new RENAME TO identities;

-- Recreate regular indexes
CREATE INDEX idx_identities_user ON identities(user_id);
CREATE INDEX idx_identities_provider_user ON identities(provider, provider_user_id);
CREATE INDEX idx_identities_expires_at ON identities(expires_at);
CREATE INDEX idx_identities_encryption_key ON identities(encryption_key_id);
CREATE INDEX idx_identities_issuing_org ON identities(issuing_org_id);
CREATE INDEX idx_identities_issuing_service ON identities(issuing_service_id);

-- Recreate partial unique indexes for context-specific isolation
-- Platform identities: one per (user, provider) when both org and service are NULL
CREATE UNIQUE INDEX idx_identities_platform_unique
ON identities(user_id, provider)
WHERE issuing_org_id IS NULL AND issuing_service_id IS NULL;

-- Service identities: one per (user, provider, service) when both are NOT NULL
CREATE UNIQUE INDEX idx_identities_service_unique
ON identities(user_id, provider, issuing_org_id, issuing_service_id)
WHERE issuing_org_id IS NOT NULL AND issuing_service_id IS NOT NULL;

-- NEW: Prevent different users from claiming the same external identity in the same context
-- This ensures that within a specific context (platform or service), a provider_user_id
-- maps to only one internal user
CREATE UNIQUE INDEX idx_identities_provider_context_unique
ON identities(provider, provider_user_id, COALESCE(issuing_org_id, ''), COALESCE(issuing_service_id, ''));

-- Re-enable foreign keys
PRAGMA foreign_keys=ON;

-- Result: Bob can now use his GitHub account (provider_user_id=15129817) as both:
-- 1. Platform admin: (user_id=bob, provider=github, issuing_org_id=NULL, issuing_service_id=NULL)
-- 2. Mitten end-user: (user_id=bob, provider=github, issuing_org_id=amp-dev-id, issuing_service_id=mitten-id)
-- Each context maintains separate tokens and isolation while sharing the same external identity
