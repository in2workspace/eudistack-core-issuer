-- =============================================================================
-- V1__signing_spki_reservation.sql
-- EUD-289 / EUD-251 AD-10: one public key, one tenant. Reserves the SHA-256 of the
-- SubjectPublicKeyInfo (SPKI) of every own-key signing certificate, so the same
-- key cannot be onboarded for two tenants.
--
-- Why it lives in public: every tenant has its own schema, and a unique index inside
-- one tenant schema cannot see the rows of another tenant. A single table shared by
-- all tenants is the only place where the primary key can reject a duplicate.
--
-- Who writes it: the onboarding tool, not the Issuer runtime (which never reads it).
-- It inserts the reservation in the same transaction that activates the own-key
-- configuration and deletes it, in the same transaction, when that configuration is
-- withdrawn. A duplicate SPKI makes the insert fail and the onboarding is rejected;
-- when two onboardings race, the primary key decides which one wins.
--
-- * public_key_spki_sha256: SHA-256 of the DER SPKI of the certificate's public key,
--   always 32 bytes.
-- * tenant_id: the tenant that holds the key, as tenant_registry.schema_name (the
--   value of the tenant in the request context, for example 'cgcom'; not the
--   '<tenant>_issuer' schema name). No foreign key: tenant_registry is provisioned
--   by the platform, not by the Issuer.
-- * signing_configuration_id: id of the tenant_signing_config row of that tenant
--   that holds the key. It points into a tenant schema, so it cannot be a foreign key.
--
-- No backfill: no own-key rows exist outside local environments, so there is nothing
-- to reserve yet.
--
-- Applied by TenantSchemaFlywayMigrator once per startup, before the tenant schemas,
-- with its own history table (flyway_issuer_public_history).
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.signing_spki_reservation (
    public_key_spki_sha256   BYTEA        PRIMARY KEY,
    tenant_id                VARCHAR(100) NOT NULL,
    signing_configuration_id UUID         NOT NULL,
    reserved_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT signing_spki_reservation_sha256_len_chk CHECK (octet_length(public_key_spki_sha256) = 32)
);
