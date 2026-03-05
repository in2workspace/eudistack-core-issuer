-- =============================================================================
-- V14: Enable Row-Level Security for tenant isolation on credential_procedure
--
-- Strategy:
--   - RLS on credential_procedure using organization_identifier as tenant key
--   - Application sets: SET LOCAL app.current_tenant = 'VATES-B12345678'
--   - Wildcard '*' bypasses RLS for system operations (schedulers, admin)
--   - Table owner (used by Flyway) is BYPASSRLS by default
--   - R2DBC user needs FORCE ROW LEVEL SECURITY if same as table owner
-- =============================================================================

-- 1. Enable RLS on credential_procedure
ALTER TABLE issuer.credential_procedure ENABLE ROW LEVEL SECURITY;

-- 2. Force RLS even for the table owner (the R2DBC connection user)
ALTER TABLE issuer.credential_procedure FORCE ROW LEVEL SECURITY;

-- 3. Policy: allow access only when app.current_tenant matches organization_identifier
--    or when app.current_tenant = '*' (system bypass)
CREATE POLICY tenant_isolation ON issuer.credential_procedure
    USING (
        current_setting('app.current_tenant', true) = organization_identifier
        OR current_setting('app.current_tenant', true) = '*'
    );

-- 4. Add index on organization_identifier for RLS performance
CREATE INDEX IF NOT EXISTS idx_credential_procedure_org_id
    ON issuer.credential_procedure (organization_identifier);
