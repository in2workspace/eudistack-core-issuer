ALTER TABLE issuance ADD COLUMN delivery_attempted_at TIMESTAMPTZ;
CREATE INDEX idx_issuance_delivery_attempted ON issuance (delivery_attempted_at) WHERE delivery_attempted_at IS NOT NULL;
