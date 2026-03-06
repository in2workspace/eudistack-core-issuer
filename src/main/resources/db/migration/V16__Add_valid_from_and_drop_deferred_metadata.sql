-- Add valid_from for credential activation lifecycle (ISSUED → VALID scheduler)
ALTER TABLE issuer.credential_procedure ADD COLUMN valid_from TIMESTAMP;

-- Drop notification_id column (moved to in-memory cache in previous refactor)
ALTER TABLE issuer.credential_procedure DROP COLUMN IF EXISTS notification_id;

-- Drop deferred_credential_metadata table (fields no longer used in current flow)
DROP TABLE IF EXISTS issuer.deferred_credential_metadata;
