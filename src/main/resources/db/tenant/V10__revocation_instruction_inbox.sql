-- =============================================================================
-- V10__revocation_instruction_inbox.sql
-- EUD-225: message-level idempotency (AD-4) for revocation instructions received
-- from the revocation-instruction message queue. The primary key on message_id
-- is what makes the claim() operation atomic across replicas (INSERT ... ON
-- CONFLICT DO NOTHING).
-- =============================================================================
CREATE TABLE IF NOT EXISTS revocation_instruction_inbox (
    message_id      TEXT         PRIMARY KEY,
    issuance_id     UUID         NOT NULL,
    status          TEXT         NOT NULL,
    claimed_at      TIMESTAMPTZ  NOT NULL,
    processed_at    TIMESTAMPTZ  NULL,
    attempts        INTEGER      NOT NULL DEFAULT 1,
    CONSTRAINT chk_revocation_instruction_inbox_status CHECK (
        status IN ('IN_PROGRESS', 'PROCESSED', 'SKIPPED')
    )
);

-- Supports detection of expired in-progress claims (NFR-S-225-04) and a future
-- purge job (deuda técnica declarada, technical-design.md §3.7.2 R-7).
CREATE INDEX IF NOT EXISTS idx_revocation_instruction_inbox_status_claimed_at
    ON revocation_instruction_inbox (status, claimed_at);
