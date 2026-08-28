-- =============================================================================
-- tenant-registry-init.sql
-- Testcontainers init script (Testcontainers#withInitScript), executed via
-- JDBC right after the container starts and BEFORE the Spring context boots.
--
-- public.tenant_registry is NOT owned by the Issuer in production (see
-- platform-dev/postgres/init-databases.sh). It must exist here too because
-- TenantSchemaFlywayMigrator (an ApplicationRunner) reads it on startup to
-- decide which <tenant>_issuer schemas to create and Flyway-migrate — without
-- this seed, no tenant schema (and therefore no api_client table) exists.
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.tenant_registry (
    schema_name   VARCHAR(64)  PRIMARY KEY,
    display_name  VARCHAR(255) NOT NULL,
    tenant_type   VARCHAR(20)  NOT NULL DEFAULT 'simple',
    status        VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

INSERT INTO public.tenant_registry (schema_name, display_name, tenant_type) VALUES
    ('e2e',          'IT Test Tenant',   'simple'),
    ('e2e-tenant-a', 'IT Test Tenant A', 'simple'),
    ('e2e-tenant-b', 'IT Test Tenant B', 'simple');
