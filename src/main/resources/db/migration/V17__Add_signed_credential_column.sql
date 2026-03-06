-- Add column to store the signed credential (JWT/SD-JWT) after successful issuance
ALTER TABLE issuer.credential_procedure ADD COLUMN signed_credential TEXT;
