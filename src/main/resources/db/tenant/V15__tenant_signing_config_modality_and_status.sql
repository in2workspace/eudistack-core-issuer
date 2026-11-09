-- =============================================================================
-- V15__tenant_signing_config_modality_and_status.sql
-- Adds the signing modality (QTSP or own key in AWS KMS) and the lifecycle
-- status to tenant_signing_config.
--
-- * modality: 'qtsp' (remote CSC provider, current behaviour) or 'own_key'.
--   For own_key rows `provider` holds 'aws-kms' (the column stays NOT NULL),
--   and only for them. A qtsp row needs provider_specific_config.
-- * status: 'active' or 'withdrawn'. Rows are never deleted: a replaced or
--   withdrawn configuration stays as history. At most one row is 'active'
--   per tenant schema (partial unique index).
--
-- Existing rows: the newest one (created_at, then id) stays qtsp/active; any
-- older row (seeds run without a unique constraint and have left duplicates in
-- some schemas) becomes withdrawn. This runs BEFORE the unique index is
-- created, otherwise the index creation would fail on those schemas.
--
-- Older rows without provider_specific_config are deleted first. They predate
-- V5, which dropped the remote_* columns that held their configuration: they
-- cannot sign and cannot be reactivated, and the qtsp check below would
-- reject them. Only rows that are not the newest of their schema are deleted:
-- a newest row without configuration (a tenant that cannot sign today) still
-- makes this migration fail, and has to be fixed before deploying.
-- =============================================================================
ALTER TABLE tenant_signing_config
    ADD COLUMN IF NOT EXISTS modality VARCHAR(20) NOT NULL DEFAULT 'qtsp',
    ADD COLUMN IF NOT EXISTS status   VARCHAR(20) NOT NULL DEFAULT 'active';

-- Data migration: older rows left without configuration by V5 are deleted.
DELETE FROM tenant_signing_config t
USING (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS rn
    FROM tenant_signing_config
) r
WHERE t.id = r.id
  AND r.rn > 1
  AND t.modality = 'qtsp'
  AND t.provider_specific_config IS NULL;

-- Data migration: newest row stays active, older ones are withdrawn.
UPDATE tenant_signing_config t
SET status = 'withdrawn'
FROM (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS rn
    FROM tenant_signing_config
) r
WHERE t.id = r.id
  AND r.rn > 1;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_tenant_signing_config_modality'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_modality
            CHECK (modality IN ('qtsp', 'own_key'));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_tenant_signing_config_status'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_status
            CHECK (status IN ('active', 'withdrawn'));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_tenant_signing_config_qtsp_required'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_qtsp_required
            CHECK (modality <> 'qtsp' OR provider_specific_config IS NOT NULL);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_tenant_signing_config_provider_modality'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_provider_modality
            CHECK ((modality = 'own_key') = (provider = 'aws-kms'));
    END IF;
END $$;

-- At most one active row per tenant schema.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_signing_config_single_active
    ON tenant_signing_config (status)
    WHERE status = 'active';
