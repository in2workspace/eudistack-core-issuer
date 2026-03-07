-- =============================================================================
-- Rename credential_procedure -> issuance
-- =============================================================================

-- 1. Drop RLS policy (must drop before rename)
DROP POLICY IF EXISTS tenant_isolation ON issuer.credential_procedure;

-- 2. Drop indexes (will recreate with new names)
DROP INDEX IF EXISTS issuer.idx_credential_procedure_credential_offer_refresh_token;
DROP INDEX IF EXISTS issuer.idx_credential_procedure_org_id;

-- 3. Rename table
ALTER TABLE issuer.credential_procedure RENAME TO issuance;

-- 4. Rename primary key column
ALTER TABLE issuer.issuance RENAME COLUMN procedure_id TO issuance_id;

-- 5. Recreate indexes with new names
CREATE UNIQUE INDEX idx_issuance_credential_offer_refresh_token
    ON issuer.issuance (credential_offer_refresh_token)
    WHERE credential_offer_refresh_token IS NOT NULL;

CREATE INDEX idx_issuance_org_id
    ON issuer.issuance (organization_identifier);

-- 6. Recreate RLS policy on renamed table
ALTER TABLE issuer.issuance ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuer.issuance FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON issuer.issuance
    USING (
        current_setting('app.current_tenant', true) = organization_identifier
        OR current_setting('app.current_tenant', true) = '*'
    );

-- 7. Rename FK column in status_list_index and its constraint/index
ALTER TABLE issuer.status_list_index RENAME COLUMN procedure_id TO issuance_id;

ALTER TABLE issuer.status_list_index
    DROP CONSTRAINT IF EXISTS uq_status_list_index_procedure_id;

ALTER TABLE issuer.status_list_index
    ADD CONSTRAINT uq_status_list_index_issuance_id UNIQUE (issuance_id);
