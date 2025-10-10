-- ============================================================================
-- ADMIN AUTHENTICATION & BRING YOUR OWN OAUTH (BYOO)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Part 1: Administrative Authentication
-- ----------------------------------------------------------------------------

-- Add is_admin_flow column to oauth_states to differentiate between admin and end-user login flows
ALTER TABLE oauth_states ADD COLUMN is_admin_flow BOOLEAN NOT NULL DEFAULT 0;

-- ----------------------------------------------------------------------------
-- Part 2: Bring Your Own OAuth (BYOO)
-- ----------------------------------------------------------------------------

-- Create table to store per-organization OAuth credentials
CREATE TABLE organization_oauth_credentials (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_encrypted BLOB NOT NULL,
    encryption_key_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, provider)
);

-- Add redirect_uris column to services table for security
ALTER TABLE services ADD COLUMN redirect_uris TEXT;

-- Create index for organization_oauth_credentials
CREATE INDEX idx_org_oauth_creds_org ON organization_oauth_credentials(org_id);
CREATE INDEX idx_org_oauth_creds_provider ON organization_oauth_credentials(org_id, provider);
