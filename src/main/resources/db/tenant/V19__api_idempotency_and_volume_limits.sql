-- =============================================================================
-- V19__api_idempotency_and_volume_limits.sql
-- EUD-269: idempotency keys and volume-limit counters of the management APIs,
-- shared by every issuer instance and kept across restarts. Both tables are
-- tenant-scoped (search_path), like every other table of the issuer.
-- =============================================================================

-- Idempotency of POST /api/v1/issuances (FR-08 of EUD-254). The primary key is
-- what makes the claim atomic across instances (INSERT ... ON CONFLICT).
--   scope_key    SHA-256 of the requester and the X-Idempotency-Key: neither the
--                person nor the organization are kept in clear.
--   request_hash SHA-256 of the canonical request body: same key, other body ->
--                idempotency_key_reused.
--   owner_id     the request that holds the key while it is IN_PROGRESS.
--   locked_until end of that request's lease; afterwards a retry with the same
--                body may take the key over (an instance stopped mid-request).
--   expires_at   end of the 24-hour retention.
-- Only successful responses are kept (state COMPLETED): a failed request deletes
-- its row, so a retry is processed again.
CREATE TABLE IF NOT EXISTS api_idempotency_record (
    scope_key              VARCHAR(64)   PRIMARY KEY,
    request_hash           VARCHAR(64)   NOT NULL,
    state                  VARCHAR(16)   NOT NULL,
    owner_id               UUID          NOT NULL,
    locked_until           TIMESTAMPTZ   NOT NULL,
    expires_at             TIMESTAMPTZ   NOT NULL,
    created_at             TIMESTAMPTZ   NOT NULL,
    response_status        INTEGER       NULL,
    response_content_type  VARCHAR(255)  NULL,
    response_location      VARCHAR(2048) NULL,
    response_body          BYTEA         NULL,
    CONSTRAINT chk_api_idempotency_record_state CHECK (state IN ('IN_PROGRESS', 'COMPLETED')),
    CONSTRAINT chk_api_idempotency_record_response CHECK (
        state = 'IN_PROGRESS' OR (response_status BETWEEN 200 AND 299 AND response_body IS NOT NULL)
    )
);

-- Purge of the expired keys.
CREATE INDEX IF NOT EXISTS idx_api_idempotency_record_expires_at
    ON api_idempotency_record (expires_at);

-- Volume limits (FR-09 of EUD-254, FR-07 of EUD-247, §5 of EUD-255): one row per
-- counter and bucket of one second (window_start); the limit is decided over the
-- sum of the buckets of the last minute (sliding window).
--   counter_key  the operation and the SHA-256 of the requester (an organization
--                for its systems, a person within its organization).
CREATE TABLE IF NOT EXISTS api_volume_counter (
    counter_key    VARCHAR(100)  NOT NULL,
    window_start   TIMESTAMPTZ   NOT NULL,
    request_count  INTEGER       NOT NULL,
    PRIMARY KEY (counter_key, window_start)
);

-- Purge of the windows that no longer count.
CREATE INDEX IF NOT EXISTS idx_api_volume_counter_window_start
    ON api_volume_counter (window_start);
