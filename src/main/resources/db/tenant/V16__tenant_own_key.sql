-- =============================================================================
-- V16__tenant_own_key.sql
-- Moves the own-key block of tenant_signing_config (V15) to a table of its own,
-- tenant_own_key, one row per own_key configuration (EUD-251 design §5.1).
-- tenant_signing_config keeps what every configuration has, whatever its
-- modality: modality, status, who and when activated and withdrew it.
--
-- * signing_configuration_id: primary key, and foreign key to the configuration
--   it belongs to. The foreign key also takes the modality, fixed to
--   'own_key' here, so a row can only belong to an own_key configuration.
-- * kms_key_ref: always the full ARN of a KMS key (as in V15).
-- * certificate_chain: the exact JWS `x5c` value (JSONB array of base64 DER
--   certificates, leaf first, root excluded). It is what signing uses: the
--   certificate_* columns are read from its leaf when the onboarding tool
--   writes the row, for queries and operations only, and nothing reads them to
--   sign. They are NULL for the rows moved from V15, which had no such columns
--   (only local environments had own_key rows).
-- * loaded_at: when the key was put into service; deleted_at: when the key of a
--   withdrawn configuration was handled by reconcile; operation_id: the
--   onboarding run that activated the configuration (the correlation id of its
--   audit events).
--
-- Every own_key configuration needs its tenant_own_key row: a constraint
-- trigger checks it at commit, so the configuration and its row are written in
-- the same transaction, in either order.
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'uq_tenant_signing_config_id_modality'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT uq_tenant_signing_config_id_modality UNIQUE (id, modality);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS tenant_own_key (
    signing_configuration_id   UUID          PRIMARY KEY,
    modality                   VARCHAR(20)   NOT NULL DEFAULT 'own_key',
    kms_key_ref                VARCHAR(2048) NOT NULL,
    algorithm                  VARCHAR(20)   NOT NULL,
    certificate_chain          JSONB         NOT NULL,
    certificate_subject        VARCHAR(1024),
    certificate_issuer         VARCHAR(1024),
    certificate_serial_number  VARCHAR(128),
    certificate_not_before     TIMESTAMPTZ,
    certificate_not_after      TIMESTAMPTZ,
    loaded_at                  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deleted_at                 TIMESTAMPTZ,
    operation_id               VARCHAR(64),
    CONSTRAINT chk_tenant_own_key_modality CHECK (modality = 'own_key'),
    CONSTRAINT chk_tenant_own_key_kms_key_ref
        CHECK (kms_key_ref ~ '^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$'),
    CONSTRAINT chk_tenant_own_key_certificate_chain
        CHECK (jsonb_typeof(certificate_chain) = 'array' AND jsonb_array_length(certificate_chain) > 0),
    CONSTRAINT chk_tenant_own_key_certificate_details
        CHECK ((certificate_subject IS NULL) = (certificate_issuer IS NULL)
           AND (certificate_subject IS NULL) = (certificate_serial_number IS NULL)
           AND (certificate_subject IS NULL) = (certificate_not_before IS NULL)
           AND (certificate_subject IS NULL) = (certificate_not_after IS NULL)),
    CONSTRAINT fk_tenant_own_key_configuration FOREIGN KEY (signing_configuration_id, modality)
        REFERENCES tenant_signing_config (id, modality)
);

-- Data migration: the own-key block of every own_key row (V15 required it on them).
INSERT INTO tenant_own_key (signing_configuration_id, kms_key_ref, algorithm, certificate_chain,
                            loaded_at, deleted_at, operation_id)
SELECT id, own_key_kms_key_ref, own_key_algorithm, own_key_certificate_chain,
       COALESCE(own_key_loaded_at, activated_at, created_at), own_key_deleted_at, own_key_operation_id
FROM tenant_signing_config
WHERE modality = 'own_key'
ON CONFLICT (signing_configuration_id) DO NOTHING;

-- The own-key block leaves tenant_signing_config. An own_key configuration still
-- needs who activated it.
ALTER TABLE tenant_signing_config
    DROP CONSTRAINT IF EXISTS chk_tenant_signing_config_own_key_required,
    DROP CONSTRAINT IF EXISTS chk_tenant_signing_config_own_key_kms_key_ref;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_tenant_signing_config_own_key_activated_by'
                     AND conrelid = 'tenant_signing_config'::regclass) THEN
        ALTER TABLE tenant_signing_config
            ADD CONSTRAINT chk_tenant_signing_config_own_key_activated_by
            CHECK (modality <> 'own_key' OR activated_by IS NOT NULL);
    END IF;
END $$;

ALTER TABLE tenant_signing_config
    DROP COLUMN IF EXISTS own_key_kms_key_ref,
    DROP COLUMN IF EXISTS own_key_algorithm,
    DROP COLUMN IF EXISTS own_key_certificate_chain,
    DROP COLUMN IF EXISTS own_key_loaded_at,
    DROP COLUMN IF EXISTS own_key_deleted_at,
    DROP COLUMN IF EXISTS own_key_operation_id;

-- Every own_key configuration has its tenant_own_key row, checked at commit. The
-- table is looked up in the schema of the row that fired the trigger, whatever the
-- search_path of the session (the onboarding tool qualifies every table).
CREATE OR REPLACE FUNCTION tenant_signing_config_own_key_present() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
DECLARE
    present BOOLEAN;
BEGIN
    IF NEW.modality = 'own_key' THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.tenant_own_key WHERE signing_configuration_id = $1)',
                       TG_TABLE_SCHEMA)
            INTO present
            USING NEW.id;
        IF NOT present THEN
            RAISE EXCEPTION 'own_key signing configuration % has no tenant_own_key row', NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NULL;
END
$fn$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgname = 'trg_tenant_signing_config_own_key_present'
                     AND tgrelid = 'tenant_signing_config'::regclass) THEN
        CREATE CONSTRAINT TRIGGER trg_tenant_signing_config_own_key_present
            AFTER INSERT OR UPDATE OF modality ON tenant_signing_config
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION tenant_signing_config_own_key_present();
    END IF;
END $$;
