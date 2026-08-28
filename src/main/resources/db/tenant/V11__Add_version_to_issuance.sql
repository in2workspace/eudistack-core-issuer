-- =============================================================================
-- V11__Add_version_to_issuance.sql
-- EUD-225 (SD-04): optimistic locking for the issuance table. Every issuanceRepository
-- .save() call site (updateIssuanceStatusToRevoked, updateIssuanceStatusToValidByIssuanceId,
-- updateCredentialDataSetByIssuanceId, withdrawIssuance, archiveIssuance, updateIssuance,
-- CredentialExpirationScheduler) follows find -> validateTransition against an in-memory
-- snapshot -> mutate -> save, with no protection against a concurrent writer winning the
-- same race in between. Verified reproducible under real concurrency by EUD-225's T28
-- (queue-vs-operator revoke race) -- see spec-deltas.md SD-04. Spring Data R2DBC manages
-- this column automatically: a stale write now fails fast with
-- OptimisticLockingFailureException instead of a silent lost update.
-- =============================================================================
ALTER TABLE issuance
    ADD COLUMN IF NOT EXISTS version BIGINT;

-- Backfill pre-existing rows so version is never unexpectedly null.
UPDATE issuance
   SET version = 0
 WHERE version IS NULL;

ALTER TABLE issuance
     ALTER COLUMN version SET DEFAULT 0,
     ALTER COLUMN version SET NOT NULL;
