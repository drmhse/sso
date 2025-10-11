-- Add device_user_code field to oauth_states table
-- This field stores the user_code from device flow so we can authorize the correct device
ALTER TABLE oauth_states ADD COLUMN device_user_code TEXT;
