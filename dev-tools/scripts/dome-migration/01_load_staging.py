#!/usr/bin/env python3
"""
01_load_staging.py — Step 1 of 3.

Reads the manually-extracted CSV from IONOS and loads it verbatim into
dome_issuer.issuance_staging.  Idempotent: re-runs skip already-loaded rows.

Usage:
    python 01_load_staging.py --csv /path/to/credential_procedure.csv
    # or set CSV_INPUT_PATH env var and run without --csv
"""

import argparse
import csv
import logging
import sys

import psycopg2
import psycopg2.extras

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Ordered list of columns in the source CSV (must match COPY extraction order).
CSV_COLUMNS = [
    "procedure_id",
    "credential_id",
    "credential_format",
    "credential_decoded",
    "credential_encoded",
    "credential_status",
    "organization_identifier",
    "subject",
    "valid_until",
    "credential_type",
    "operation_mode",
    "signature_mode",
    "email",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "notification_id",
]

# ── DDL ───────────────────────────────────────────────────────────────────────

CREATE_STAGING_DDL = """
CREATE TABLE IF NOT EXISTS dome_issuer.issuance_staging (
    procedure_id            uuid                        NOT NULL,
    credential_id           uuid,
    credential_format       character varying(20),
    credential_decoded      text,
    credential_encoded      text,
    credential_status       character varying(20),
    organization_identifier character varying(255),
    subject                 character varying(255),
    valid_until             timestamp without time zone,
    credential_type         character varying(50),
    operation_mode          character varying(20),
    signature_mode          character varying(20),
    email                   character varying(255),
    created_at              timestamp with time zone,
    created_by              character varying(320),
    updated_at              timestamp with time zone,
    updated_by              character varying(320),
    notification_id         uuid,
    staging_loaded_at       timestamp with time zone    DEFAULT now(),
    PRIMARY KEY (procedure_id)
);
"""

INSERT_STAGING_SQL = """
INSERT INTO dome_issuer.issuance_staging (
    procedure_id, credential_id, credential_format,
    credential_decoded, credential_encoded, credential_status,
    organization_identifier, subject, valid_until, credential_type,
    operation_mode, signature_mode, email,
    created_at, created_by, updated_at, updated_by, notification_id
) VALUES (
    %(procedure_id)s, %(credential_id)s, %(credential_format)s,
    %(credential_decoded)s, %(credential_encoded)s, %(credential_status)s,
    %(organization_identifier)s, %(subject)s, %(valid_until)s, %(credential_type)s,
    %(operation_mode)s, %(signature_mode)s, %(email)s,
    %(created_at)s, %(created_by)s, %(updated_at)s, %(updated_by)s, %(notification_id)s
)
ON CONFLICT (procedure_id) DO NOTHING;
"""

# ── Helpers ───────────────────────────────────────────────────────────────────


def verify_schema(conn: "psycopg2.connection") -> None:
    """Abort with a clear message if dome_issuer schema is missing."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'dome_issuer'"
        )
        if cur.fetchone() is None:
            log.error(
                "Schema 'dome_issuer' does not exist in the target database.\n"
                "Run the corresponding Flyway migration (e.g. V2__create_dome_issuer_schema.sql) "
                "on the target DB before executing this script."
            )
            sys.exit(2)


def parse_csv(path: str) -> list[dict]:
    """
    Read the CSV and return a list of row dicts.
    Empty strings are converted to None so psycopg2 inserts NULL.
    Sensitive fields (credential_decoded, credential_encoded) are never logged.
    """
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        # Validate that expected columns are present
        if reader.fieldnames is None:
            log.error("CSV file appears to be empty: %s", path)
            sys.exit(1)

        missing = set(CSV_COLUMNS) - set(reader.fieldnames)
        if missing:
            log.error(
                "CSV is missing expected columns: %s\n"
                "Expected: %s\nFound: %s",
                sorted(missing),
                CSV_COLUMNS,
                reader.fieldnames,
            )
            sys.exit(1)

        for row in reader:
            rows.append({k: (v if v != "" else None) for k, v in row.items()})

    return rows


# ── Main logic ────────────────────────────────────────────────────────────────


def run(csv_path: str) -> None:
    log.info("Connecting to target DB (%s:%s/%s)…", config.DB_HOST, config.DB_PORT, config.DB_NAME)
    conn = config.get_db_connection()

    try:
        verify_schema(conn)

        log.info("Ensuring staging table exists…")
        with conn.cursor() as cur:
            cur.execute(CREATE_STAGING_DDL)
        conn.commit()

        log.info("Reading CSV: %s", csv_path)
        rows = parse_csv(csv_path)
        total = len(rows)
        log.info("Rows read from CSV: %d", total)

        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {config.STAGING_TABLE}")
            count_before: int = cur.fetchone()[0]

        log.info("Loading rows into staging (chunk size %d)…", config.CHUNK_SIZE)
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(cur, INSERT_STAGING_SQL, rows, page_size=config.CHUNK_SIZE)
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {config.STAGING_TABLE}")
            count_after: int = cur.fetchone()[0]

        inserted = count_after - count_before
        skipped  = total - inserted

        print()
        print("─── 01_load_staging  summary ────────────────────")
        print(f"  Total rows in CSV  : {total}")
        print(f"  Rows inserted      : {inserted}")
        print(f"  Rows skipped       : {skipped}  (already existed — ON CONFLICT DO NOTHING)")
        print("─────────────────────────────────────────────────")

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Load source CSV into dome_issuer.issuance_staging (step 1/3)."
    )
    parser.add_argument(
        "--csv",
        dest="csv_path",
        default=config.CSV_INPUT_PATH,
        help="Path to the credential_procedure CSV file.",
    )
    args = parser.parse_args()

    if not args.csv_path:
        log.error("CSV path is required: pass --csv <path> or set CSV_INPUT_PATH env var.")
        sys.exit(1)

    run(args.csv_path)


if __name__ == "__main__":
    main()
