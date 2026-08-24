-- Add index to issuance table to optimize credential expiration scheduler
CREATE INDEX idx_issuance_expiration ON issuance (credential_status, valid_until);