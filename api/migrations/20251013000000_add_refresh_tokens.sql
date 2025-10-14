-- Add refresh token support with full session context preservation
-- This enables automatic JWT renewal without re-authentication

-- Add refresh token columns to sessions table
ALTER TABLE sessions ADD COLUMN refresh_token TEXT;
ALTER TABLE sessions ADD COLUMN refresh_token_expires_at DATETIME;

-- Add service/organization context to sessions
ALTER TABLE sessions ADD COLUMN org_slug TEXT;
ALTER TABLE sessions ADD COLUMN service_id TEXT;

-- Add created_at timestamp for session lifecycle tracking
ALTER TABLE sessions ADD COLUMN created_at DATETIME DEFAULT (datetime('now'));
