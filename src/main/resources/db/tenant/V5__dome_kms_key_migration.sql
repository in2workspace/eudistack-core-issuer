-- V5__dome_kms_key_migration.sql
-- Prerequisite tables for the DOME key-migration module (KMS migration + audit trail).

-- ---------------------------------------------------------------------------
-- Table: kms_key_migration
-- Tracks the migration lifecycle of every Vault signing key to the AWS KMS.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kms_key_migration (
                                                 id                  UUID         NOT NULL DEFAULT gen_random_uuid(),
    legacy_key_id       VARCHAR(255) NOT NULL,
    kms_alias           VARCHAR(255),
    migration_status    VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
    -- Expected values: PENDING | POC_OK | POC_FAILED | PLAN_A_OK
    --                  | PLAN_B_REISSUE | PLAN_B_PARTIAL | ROLLED_BACK | FAILED
    migrated_at         TIMESTAMPTZ,
    audit_evidence_uri  VARCHAR(1000),
    replay_attempt      INTEGER      NOT NULL DEFAULT 0,
    notes               TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_kms_key_migration               PRIMARY KEY (id),
    CONSTRAINT uq_kms_key_migration_legacy_key_id UNIQUE (legacy_key_id)
    );

CREATE INDEX IF NOT EXISTS idx_kms_key_migration_status
    ON kms_key_migration (migration_status);

-- ---------------------------------------------------------------------------
-- Table: migration_audit
-- Immutable audit log of every credential processed during plan-B re-issuance
-- and every lifecycle event emitted by CloudWatchKeyMigrationAuditAdapter.
-- The partial unique index on (source_record_id) WHERE outcome = 'OK' enforces
-- idempotence of the batch (AC-07): one successful re-issuance per credential.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS migration_audit (
                                               id               UUID        NOT NULL DEFAULT gen_random_uuid(),
    source_record_id UUID,
    target_record_id UUID,
    source_hash      VARCHAR(64),
    target_hash      VARCHAR(64),
    migrated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    replay_attempt   INTEGER     NOT NULL DEFAULT 0,
    outcome          VARCHAR(50) NOT NULL,
    -- Plan-B batch values:  OK | SKIPPED | FAILED | HASH_MISMATCH
    -- Lifecycle audit values: PLAN_A_OK | PLAN_B_REISSUE | POC_RESULT:{MigrationStatus}
    -- Longest value: POC_RESULT:PLAN_B_REISSUE (25 chars) — VARCHAR(50) provides headroom
    error_message    TEXT,

    CONSTRAINT pk_migration_audit PRIMARY KEY (id)
    );

CREATE INDEX IF NOT EXISTS idx_migration_audit_source_record_id
    ON migration_audit (source_record_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_migration_audit_source_ok
    ON migration_audit (source_record_id)
    WHERE outcome = 'OK';

CREATE INDEX IF NOT EXISTS idx_migration_audit_outcome
    ON migration_audit (outcome);