-- =============================================================================
-- V3__Status_list_tables.sql
-- Per-tenant migration: status list tables within each tenant schema.
-- Each tenant has its own status lists for credentials it issues.
-- =============================================================================

CREATE TABLE IF NOT EXISTS status_list (
    id                BIGSERIAL   PRIMARY KEY,
    purpose           TEXT        NOT NULL,
    format            VARCHAR(30) NOT NULL DEFAULT 'bitstring_vc',
    encoded_list      TEXT        NOT NULL,
    signed_credential TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_status_list_purpose_format_desc
    ON status_list (purpose, format, id DESC);

CREATE TABLE IF NOT EXISTS status_list_index (
    id             BIGSERIAL   PRIMARY KEY,
    status_list_id BIGINT      NOT NULL,
    idx            INTEGER     NOT NULL,
    issuance_id    UUID        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_status_list_index_status_list
        FOREIGN KEY (status_list_id)
        REFERENCES status_list (id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_status_list_index_issuance_id
        UNIQUE (issuance_id),

    CONSTRAINT uq_status_list_index_list_id_idx
        UNIQUE (status_list_id, idx)
);

CREATE INDEX IF NOT EXISTS idx_status_list_index_status_list_id
    ON status_list_index (status_list_id);
