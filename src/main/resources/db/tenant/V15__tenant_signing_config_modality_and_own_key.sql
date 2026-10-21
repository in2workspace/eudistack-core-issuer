-- =============================================================================
-- V15__tenant_signing_config_modality_and_own_key.sql
-- EUD-289: adds the signing modality (QTSP or own key in AWS KMS), the lifecycle
-- status and the own-key metadata block to tenant_signing_config (same table,
-- no separate own_key table).
--
-- * modality: 'qtsp' (remote CSC provider, current behaviour) or 'own_key'.
--   For own_key rows `provider` holds 'aws-kms' (the column stays NOT NULL).
-- * status: 'active' or 'withdrawn'. Rows are never deleted: a replaced or
--   withdrawn configuration stays as history. At most one row is 'active'
--   per tenant schema (partial unique index).
-- * own-key block: no secrets, only the KMS key ARN, the certificate chain as
--   the exact JWS `x5c` value (JSONB array of base64 DER certificates, leaf
--   first, root excluded), certificate metadata and the SPKI SHA-256
--   (lowercase hex, same as PublicKeyFingerprints) used for uniqueness checks.
--
-- Existing rows: the newest one (created_at, then id) stays qtsp/active; any
-- older row (seeds run without a unique constraint and have left duplicates in
-- some schemas) becomes withdrawn. This runs BEFORE the unique index is
-- created, otherwise the index creation would fail on those schemas.
--
-- The application does not read the new columns yet (R2DBC ignores unmapped
-- columns). The seed pattern `INSERT ... ON CONFLICT DO NOTHING` (no conflict
-- target) becomes a silent no-op when an active row already exists.
-- =============================================================================
ALTER TABLE tenant_signing_config
    ADD COLUMN IF NOT EXISTS modality                   VARCHAR(20) NOT NULL DEFAULT 'qtsp',
    ADD COLUMN IF NOT EXISTS status                     VARCHAR(20) NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS activated_at               TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS withdrawn_at               TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS own_key_kms_key_ref        VARCHAR(2048),
    ADD COLUMN IF NOT EXISTS own_key_algorithm          VARCHAR(20),
    ADD COLUMN IF NOT EXISTS own_key_certificate_chain  JSONB,
    ADD COLUMN IF NOT EXISTS own_key_cert_subject       VARCHAR(1000),
    ADD COLUMN IF NOT EXISTS own_key_cert_issuer        VARCHAR(1000),
    ADD COLUMN IF NOT EXISTS own_key_cert_serial        VARCHAR(128),
    ADD COLUMN IF NOT EXISTS own_key_cert_not_before    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS own_key_cert_not_after     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS own_key_spki_sha256        CHAR(64),
    ADD COLUMN IF NOT EXISTS own_key_loaded_at          TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS own_key_deleted_at         TIMESTAMPTZ;

-- Data migration: newest row stays active, older ones are withdrawn.
UPDATE tenant_signing_config t
SET status       = CASE WHEN r.rn = 1 THEN 'active' ELSE 'withdrawn' END,
    activated_at = COALESCE(t.activated_at, t.created_at),
    withdrawn_at = CASE WHEN r.rn = 1 THEN t.withdrawn_at
                        ELSE COALESCE(t.withdrawn_at, now()) END
FROM (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS rn
    FROM tenant_signing_config
) r
WHERE t.id = r.id
  AND t.activated_at IS NULL;

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
                   WHERE conname = 'chk_tenant_signing_config_own_key_required'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_own_key_required
            CHECK (modality <> 'own_key' OR (
                own_key_kms_key_ref IS NOT NULL
                AND own_key_algorithm IS NOT NULL
                AND own_key_spki_sha256 IS NOT NULL
                AND own_key_certificate_chain IS NOT NULL
                AND jsonb_typeof(own_key_certificate_chain) = 'array'
                AND jsonb_array_length(own_key_certificate_chain) > 0));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_tenant_signing_config_withdrawn_at'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_withdrawn_at
            CHECK (status <> 'withdrawn' OR withdrawn_at IS NOT NULL);
    END IF;
END $$;

-- At most one active row per tenant schema.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_signing_config_single_active
    ON tenant_signing_config (status)
    WHERE status = 'active';
