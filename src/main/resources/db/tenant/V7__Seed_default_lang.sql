-- =============================================================================
-- V7__Seed_default_lang.sql
-- Inserts a placeholder issuer.default_lang row in tenant_config so every tenant
-- has a value for the transactional-email language. Real per-tenant values are
-- set in the platform repo (eudistack-platform-dev: postgres/seed-tenants[.stg].sql).
-- Supported values: en|es.
-- When absent (or unsupported), the code falls back to the global APP_DEFAULT_LANG.
-- =============================================================================
INSERT INTO tenant_config (config_key, config_value, description) VALUES
    ('issuer.default_lang', 'en', 'Default language for transactional emails (en|es)')
ON CONFLICT (config_key) DO NOTHING;
