-- Add user_id_for_linking column to oauth_states table
-- This column will store the ID of the logged-in user who is initiating a social account link
ALTER TABLE oauth_states ADD COLUMN user_id_for_linking TEXT NULL REFERENCES users(id);

-- Create index for faster lookups
CREATE INDEX idx_oauth_states_user_linking ON oauth_states(user_id_for_linking);
