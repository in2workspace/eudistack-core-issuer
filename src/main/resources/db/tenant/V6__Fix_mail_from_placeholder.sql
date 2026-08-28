-- =============================================================================
-- V6__Fix_mail_from_placeholder.sql
-- Corrects the issuer.mail_from placeholder: mail-stg → mail.stg
-- =============================================================================
UPDATE tenant_config
SET config_value = 'noreply@mail.stg.eudistack.net'
WHERE config_key  = 'issuer.mail_from'
  AND config_value = 'noreply@mail-stg.eudistack.net';
