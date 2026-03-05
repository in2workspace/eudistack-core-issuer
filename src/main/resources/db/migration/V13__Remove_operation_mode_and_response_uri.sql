-- Remove operation_mode from credential_procedure
ALTER TABLE issuer.credential_procedure DROP COLUMN IF EXISTS operation_mode;

-- Remove operation_mode and response_uri from deferred_credential_metadata
ALTER TABLE issuer.deferred_credential_metadata DROP COLUMN IF EXISTS operation_mode;
ALTER TABLE issuer.deferred_credential_metadata DROP COLUMN IF EXISTS response_uri;
