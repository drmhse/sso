-- Add created_at column to identities table, allowing NULL for now.
ALTER TABLE identities ADD COLUMN created_at DATETIME;

-- Backfill the created_at for all existing rows with the current time.
UPDATE identities SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;
