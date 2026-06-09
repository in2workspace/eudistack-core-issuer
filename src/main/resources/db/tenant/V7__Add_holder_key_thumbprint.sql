-- =============================================================================
-- V7__Add_holder_key_thumbprint.sql
-- EUDISTACK-144: Add column and index for DOME auto-recovery by Passkey thumbprint
-- =============================================================================

ALTER TABLE issuance ADD COLUMN IF NOT EXISTS holder_key_thumbprint VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_issuance_holder_key_thumbprint
    ON issuance (holder_key_thumbprint)
    WHERE holder_key_thumbprint IS NOT NULL;