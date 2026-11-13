-- =============================================================================
-- V20__Add_last_changed_at_to_issuance.sql
-- EUD-255 design 1.1, AD-2 and §5: the issuance process gets its own "last
-- change" -- its creation or its last change of state -- which the query API
-- orders and paginates by, and returns as `updated`. updated_at is not reused:
-- it also moves on technical writes (delivery attempt, offer renewal, version).
--
-- * Existing rows are backfilled from updated_at (created_at, then now(), for a
--   row that never had one).
-- * DEFAULT now() covers an insert that does not set it; the application sets
--   it itself on creation and on every change of state.
-- * Indexes for keyset pagination (AD-1): the whole tenant, and one
--   organization.
--
-- Version number provisional: V19 is taken by EUD-269 (unmerged) and the
-- issuance API migrations go first (design §5). Renumber before merging.
-- Idempotent.
-- =============================================================================

ALTER TABLE issuance ADD COLUMN IF NOT EXISTS last_changed_at TIMESTAMPTZ;

UPDATE issuance
   SET last_changed_at = COALESCE(updated_at, created_at, now())
 WHERE last_changed_at IS NULL;

ALTER TABLE issuance ALTER COLUMN last_changed_at SET DEFAULT now();
ALTER TABLE issuance ALTER COLUMN last_changed_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_issuance_last_changed
    ON issuance (last_changed_at DESC, issuance_id DESC);

CREATE INDEX IF NOT EXISTS idx_issuance_org_last_changed
    ON issuance (organization_identifier, last_changed_at DESC, issuance_id DESC);
