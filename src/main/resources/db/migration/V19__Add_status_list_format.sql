-- Add format column to distinguish BitstringStatusList (W3C) from TokenStatusList (SD-JWT)
ALTER TABLE issuer.status_list
    ADD COLUMN format VARCHAR(30) NOT NULL DEFAULT 'bitstring_vc';

-- Replace purpose-only index with composite purpose+format index for efficient lookups
DROP INDEX IF EXISTS issuer.idx_status_list_desc;
CREATE INDEX idx_status_list_purpose_format_desc
    ON issuer.status_list (purpose, format, id DESC);
