-- Add issuing_service_id column to identities table for proper service-level isolation
-- This migration fixes a critical security flaw where identities were only isolated at org-level
-- Now each identity is scoped to either platform (both NULL) or specific service (both NOT NULL)

-- Step 1: Add the issuing_service_id column
ALTER TABLE identities ADD COLUMN issuing_service_id TEXT NULL REFERENCES services(id);

-- Step 2: Create index for performance
CREATE INDEX idx_identities_issuing_service ON identities(issuing_service_id);

-- Step 3: Migrate existing data
-- All existing identities with issuing_org_id should have their service_id set to the FIRST service of that org
-- This is a best-effort migration - admin should review and correct if needed
UPDATE identities
SET issuing_service_id = (
    SELECT id FROM services
    WHERE org_id = identities.issuing_org_id
    ORDER BY created_at ASC
    LIMIT 1
)
WHERE issuing_org_id IS NOT NULL;

-- Step 4: Drop the old unique constraint on (user_id, provider)
-- First, we need to check the name of the existing unique constraint
-- In SQLite, UNIQUE constraints create indexes, so we need to find and drop them
-- The constraint was likely created as part of the table definition, so we need to recreate the table

-- Temporarily disable foreign keys
PRAGMA foreign_keys=OFF;

-- Create new identities table with correct constraints
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
    issuing_service_id TEXT REFERENCES services(id),
    -- Uniqueness: provider_user_id should map to only one user globally
    UNIQUE(provider, provider_user_id)
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

-- Recreate indexes
CREATE INDEX idx_identities_user ON identities(user_id);
CREATE INDEX idx_identities_provider_user ON identities(provider, provider_user_id);
CREATE INDEX idx_identities_expires_at ON identities(expires_at);
CREATE INDEX idx_identities_encryption_key ON identities(encryption_key_id);
CREATE INDEX idx_identities_issuing_org ON identities(issuing_org_id);
CREATE INDEX idx_identities_issuing_service ON identities(issuing_service_id);

-- Step 5: Create partial unique indexes for proper isolation
-- Platform identities: one per (user, provider) when both org and service are NULL
CREATE UNIQUE INDEX idx_identities_platform_unique
ON identities(user_id, provider)
WHERE issuing_org_id IS NULL AND issuing_service_id IS NULL;

-- Service identities: one per (user, provider, service) when both are NOT NULL
CREATE UNIQUE INDEX idx_identities_service_unique
ON identities(user_id, provider, issuing_org_id, issuing_service_id)
WHERE issuing_org_id IS NOT NULL AND issuing_service_id IS NOT NULL;

-- Re-enable foreign keys
PRAGMA foreign_keys=ON;

-- Note: After this migration, admin should verify that:
-- 1. Platform identities have both issuing_org_id and issuing_service_id as NULL
-- 2. Service identities have both issuing_org_id and issuing_service_id set correctly
-- 3. No orphaned identities exist (where one is NULL and the other is NOT NULL)
