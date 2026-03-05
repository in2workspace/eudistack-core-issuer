-- Rename credential_decoded → credential_data_set
ALTER TABLE issuer.credential_procedure RENAME COLUMN credential_decoded TO credential_data_set;

-- Drop columns that no longer belong to the business procedure
ALTER TABLE issuer.credential_procedure DROP COLUMN IF EXISTS credential_encoded;
ALTER TABLE issuer.credential_procedure DROP COLUMN IF EXISTS signature_mode;
ALTER TABLE issuer.credential_procedure DROP COLUMN IF EXISTS cnf;

-- Move cnf (holder key binding) to deferred_credential_metadata (OID4VCI transactional data)
ALTER TABLE issuer.deferred_credential_metadata ADD COLUMN IF NOT EXISTS cnf TEXT;

-- Add delivery channel tracking
ALTER TABLE issuer.credential_procedure ADD COLUMN delivery VARCHAR(10) NOT NULL DEFAULT 'email';

-- Add opaque refresh token for credential offer refresh
ALTER TABLE issuer.credential_procedure ADD COLUMN refresh_token VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_procedure_refresh_token
    ON issuer.credential_procedure (refresh_token) WHERE refresh_token IS NOT NULL;
