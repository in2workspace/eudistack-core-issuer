-- =============================================================================
-- V13__Add_delivery_modes_to_tenant_credential_profile.sql
-- EUD-169: delivery modes become a column of the tenant's credential catalog
-- (tenant_credential_profile), replacing the parallel tenant_config-based
-- module (issuer.delivery.modes.* keys). Additive, idempotent, fail-closed.
-- =============================================================================

-- 1) Additive, idempotent column (V9/V11 pattern)
ALTER TABLE tenant_credential_profile
    ADD COLUMN IF NOT EXISTS delivery_modes VARCHAR(64);

-- 2) Fail-closed GUARD (ES-08): existing configuration that CANNOT be migrated
--    without silently broadening permissions. Condition (a) is literally aligned
--    with the 7 forms allowed by the CHECK in step 4 (M4, re-verification code review):
--    previously, any order/duplication of direct/email/ui was accepted, so a
--    non-canonical legacy value could pass this guard and only fail later, in step 4,
--    with an opaque PostgreSQL constraint violation instead of this clear RAISE EXCEPTION.
DO $$
DECLARE unmigratable int;
BEGIN
    SELECT count(*) INTO unmigratable
      FROM tenant_config c
     WHERE c.config_key LIKE 'issuer.delivery.modes.%'
       AND (
            -- (a) value is not interpretable, or is interpretable but non-canonical
            c.config_value NOT IN ('direct', 'email', 'ui',
                                    'direct,email', 'direct,ui', 'email,ui',
                                    'direct,email,ui')
            -- (b) empty catalog => "empty = everything enabled": there is no row
            --     to migrate into, and creating one would invert the catalog semantics
         OR NOT EXISTS (SELECT 1 FROM tenant_credential_profile)
       );
    IF unmigratable > 0 THEN
        RAISE EXCEPTION
          'EUD-169: % delivery-mode key(s) cannot be migrated losslessly in schema %. Resolve before deploying.',
          unmigratable, current_schema();
    END IF;
END $$;

-- 3) Idempotent backfill (EC-06). Keys whose ccid is not enabled are
--    deliberately ignored: that type cannot be issued for that tenant (EC-07).
UPDATE tenant_credential_profile p
   SET delivery_modes = c.config_value,
       updated_at     = now()
  FROM tenant_config c
 WHERE c.config_key = 'issuer.delivery.modes.' || p.credential_configuration_id
   AND p.delivery_modes IS NULL;

-- 3b) EC-07 "is recorded so it can be audited": the tenant_config row is not
--     deleted (rollback safety net), but the deployment log also explicitly records
--     which keys were not migrated because they had no corresponding enabled row.
DO $$
DECLARE discarded text;
BEGIN
    SELECT string_agg(c.config_key, ', ') INTO discarded
      FROM tenant_config c
     WHERE c.config_key LIKE 'issuer.delivery.modes.%'
       AND NOT EXISTS (
           SELECT 1 FROM tenant_credential_profile p
            WHERE p.credential_configuration_id = substring(c.config_key FROM length('issuer.delivery.modes.') + 1)
       );
    IF discarded IS NOT NULL THEN
        RAISE NOTICE
          'EUD-169: discarded legacy delivery-mode key(s) for not-enabled credential_configuration_id(s) in schema %: %',
          current_schema(), discarded;
    END IF;
END $$;

-- 4) Data-level shape invariant, applied after the backfill. It enumerates exactly
--    the 7 non-empty subsets of {direct,email,ui}, in alphabetical order and without
--    duplicates -- the same canonical form that DeliveryMode.toCanonicalCsv always
--    produces before writing (code review, TD-6): a syntactically valid but
--    non-canonical CSV (duplicate, or different ordering) should never reach this
--    point, and the database itself now guarantees it instead of relying solely
--    on the application layer.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'chk_tcp_delivery_modes'
                      AND conrelid = 'tenant_credential_profile'::regclass) THEN
        ALTER TABLE tenant_credential_profile
            ADD CONSTRAINT chk_tcp_delivery_modes
            CHECK (delivery_modes IS NULL
                   OR delivery_modes IN ('direct', 'email', 'ui',
                                          'direct,email', 'direct,ui', 'email,ui',
                                          'direct,email,ui'));
    END IF;
END $$;