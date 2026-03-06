-- Rename refresh_token column to credential_offer_refresh_token for clarity
-- (avoids confusion with OAuth2 refresh_token in OID4VCI token endpoint)

DROP INDEX IF EXISTS issuer.idx_credential_procedure_refresh_token;

ALTER TABLE issuer.credential_procedure
    RENAME COLUMN refresh_token TO credential_offer_refresh_token;

CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_procedure_credential_offer_refresh_token
    ON issuer.credential_procedure (credential_offer_refresh_token)
    WHERE credential_offer_refresh_token IS NOT NULL;
