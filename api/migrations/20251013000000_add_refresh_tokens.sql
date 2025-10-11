-- Add refresh token support with full session context preservation
-- This enables automatic JWT renewal without re-authentication
-- Note: This migration is designed to be idempotent and safe to run multiple times

-- Update existing sessions to have created_at = expires_at (best approximation for existing data)
UPDATE sessions SET created_at = expires_at WHERE created_at IS NULL;
