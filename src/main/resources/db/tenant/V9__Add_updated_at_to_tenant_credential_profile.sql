-- =============================================================================
-- V9__Add_updated_at_to_tenant_credential_profile.sql
-- EUD-72 (US-02): audit column tracking the last modification of a tenant's
-- credential catalog. Set by the application on each updateCatalog() write.
-- (V7 and V8 were already taken by EUD-* stories, hence V9.)
-- =============================================================================
ALTER TABLE tenant_credential_profile
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;

-- Backfill pre-existing rows (seeds) so updated_at is never unexpectedly null.
UPDATE tenant_credential_profile
   SET updated_at = created_at
 WHERE updated_at IS NULL;

ALTER TABLE tenant_credential_profile
     ALTER COLUMN updated_at SET DEFAULT now(),
     ALTER COLUMN updated_at SET NOT NULL;