-- Add device_activation_uri to services table
-- This allows each service to specify where its device activation UI is hosted
-- If NULL, the API will fall back to base_url/activate

ALTER TABLE services ADD COLUMN device_activation_uri TEXT;
