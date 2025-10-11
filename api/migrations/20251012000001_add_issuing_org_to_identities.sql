-- Add issuing_org_id to identities table to track which credentials (platform vs BYOO) were used
ALTER TABLE identities ADD COLUMN issuing_org_id TEXT NULL REFERENCES organizations(id);

-- Add an index for performance
CREATE INDEX idx_identities_issuing_org ON identities(issuing_org_id);
