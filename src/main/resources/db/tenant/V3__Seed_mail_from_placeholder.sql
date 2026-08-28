-- =============================================================================
-- V3__Seed_mail_from_placeholder.sql
-- Inserts a placeholder issuer.mail_from row in tenant_config so every tenant
-- has a non-null value. Real values are overridden per tenant in
-- postgres/seed-tenants{.stg,.prod}.sql.
-- =============================================================================
INSERT INTO tenant_config (config_key, config_value, description) VALUES
    ('issuer.mail_from', 'noreply@mail-stg.eudistack.net', 'Sender address used for transactional emails')
ON CONFLICT (config_key) DO NOTHING;
