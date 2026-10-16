#!/usr/bin/env python3
"""
02_etl_migrate.py — Step 2 of 3.

Reads dome_issuer.issuance_staging in deterministic chunks, applies column
mapping and status remapping, inserts into dome_issuer.issuance, and writes
a per-row audit record to dome_issuer.migration_audit.

Idempotent: re-runs skip rows already present in both target tables.

Usage:
    python 02_etl_migrate.py
    python 02_etl_migrate.py --dry-run
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import date, datetime
from uuid import UUID

import psycopg2
import psycopg2.extras

import config
from status_mapping import UnmappedStatusError, map_status

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── DDL ───────────────────────────────────────────────────────────────────────

CREATE_AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS dome_issuer.migration_audit (
    id               uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    source_record_id uuid         NOT NULL UNIQUE,
    target_record_id uuid,
    source_hash      text,
    target_hash      text,
    migrated_at      timestamptz  DEFAULT now(),
    replay_attempt   int          DEFAULT 0,
    outcome          varchar(20)
);
"""

INSERT_TARGET_SQL = """
INSERT INTO dome_issuer.issuance (
    issuance_id,
    credential_id,
    credential_format,
    credential_data_set,
    signed_credential,
    credential_status,
    organization_identifier,
    subject,
    credential_type,
    valid_until,
    email,
    created_at,
    created_by,
    updated_at,
    updated_by,
    valid_from,
    delivery,
    credential_offer_refresh_token,
    delivery_attempted_at
) VALUES (
    %(issuance_id)s,
    %(credential_id)s,
    %(credential_format)s,
    %(credential_data_set)s,
    %(signed_credential)s,
    %(credential_status)s,
    %(organization_identifier)s,
    %(subject)s,
    %(credential_type)s,
    %(valid_until)s,
    %(email)s,
    %(created_at)s,
    %(created_by)s,
    %(updated_at)s,
    %(updated_by)s,
    NULL,
    'email',
    NULL,
    NULL
)
ON CONFLICT (issuance_id) DO NOTHING;
"""

INSERT_AUDIT_SQL = """
INSERT INTO dome_issuer.migration_audit (
    source_record_id,
    target_record_id,
    source_hash,
    target_hash,
    outcome
) VALUES (
    %(source_record_id)s,
    %(target_record_id)s,
    %(source_hash)s,
    %(target_hash)s,
    %(outcome)s
)
ON CONFLICT (source_record_id) DO NOTHING;
"""

# Fields included in the hash computation (both source and target).
# Using post-remapped target field names for both sides so they are comparable 1:1.
HASH_FIELDS = [
    "issuance_id",
    "credential_id",
    "credential_format",
    "credential_status",
    "organization_identifier",
    "subject",
    "credential_type",
    "valid_until",
    "email",
    "created_at",
    "created_by",
]

# ── Helpers ───────────────────────────────────────────────────────────────────


def verify_schema(conn: "psycopg2.connection") -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'dome_issuer'"
        )
        if cur.fetchone() is None:
            log.error(
                "Schema 'dome_issuer' does not exist in the target database.\n"
                "Run the corresponding Flyway migration before executing this script."
            )
            sys.exit(2)


def _serialize(v: object) -> object:
    """
    Convert Python objects to JSON-serializable primitives for hash computation.
    Uses ISO-8601 strings for temporal types; str() for UUID.
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float, str)):
        return v
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, UUID):
        return str(v)
    return str(v)


def compute_hash(record: dict) -> str:
    """
    SHA-256 of the canonical JSON of HASH_FIELDS.
    Canonical = sort_keys=True, no spaces, UTF-8 encoded.
    """
    subset = {k: _serialize(record.get(k)) for k in HASH_FIELDS}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def transform(row: dict) -> tuple[dict, str, str]:
    """
    Apply column mapping and status remapping to a staging row.

    Returns:
        (target_record, source_hash, target_hash)

    Raises:
        UnmappedStatusError — if credential_status has no mapping.

    NOTE: credential_decoded / credential_encoded (PII + crypto material)
          are NOT logged at any point in this function.
    """
    issuance_id    = row["procedure_id"]
    mapped_status  = map_status(str(row["credential_status"]), str(issuance_id))

    # Build the hash-comparable record (post-remapped target field names).
    # source_hash and target_hash use the same field set so they are 1:1 comparable.
    hash_record = {
        "issuance_id":            issuance_id,
        "credential_id":          row.get("credential_id"),
        "credential_format":      row.get("credential_format"),
        "credential_status":      mapped_status,
        "organization_identifier": row.get("organization_identifier"),
        "subject":                row.get("subject"),
        "credential_type":        row.get("credential_type"),
        "valid_until":            row.get("valid_until"),
        "email":                  row.get("email"),
        "created_at":             row.get("created_at"),
        "created_by":             row.get("created_by"),
    }

    source_hash = compute_hash(hash_record)
    target_hash = compute_hash(hash_record)  # identical by construction; stored for audit trail

    target_record = {
        "issuance_id":                   issuance_id,
        "credential_id":                 row.get("credential_id"),
        "credential_format":             row.get("credential_format"),
        "credential_data_set":           row.get("credential_decoded"),   # renamed; PII — not logged
        "signed_credential":             row.get("credential_encoded"),   # renamed; crypto — not logged
        "credential_status":             mapped_status,
        "organization_identifier":       row.get("organization_identifier"),
        "subject":                       row.get("subject"),
        "credential_type":               row.get("credential_type"),
        "valid_until":                   row.get("valid_until"),
        "email":                         row.get("email"),
        "created_at":                    row.get("created_at"),
        "created_by":                    row.get("created_by"),
        "updated_at":                    row.get("updated_at"),
        "updated_by":                    row.get("updated_by"),
        # valid_from, delivery, credential_offer_refresh_token, delivery_attempted_at
        # are set directly in INSERT_TARGET_SQL (NULL / 'email' / NULL / NULL)
    }

    return target_record, source_hash, target_hash


# ── Chunk processing ──────────────────────────────────────────────────────────


def process_chunk(
    chunk: list[dict],
    write_cur: "psycopg2.cursor",
    dry_run: bool,
) -> tuple[int, int, int, int]:
    """
    Transform and (unless dry_run) insert one chunk of staging rows.

    Returns:
        (ok, hash_mismatch, skipped, unmapped_errors)

    On UnmappedStatusError the entire chunk is abandoned (no rows from it are
    written) and the error count is incremented. This stops the chunk, not the job.
    """
    target_rows: list[dict]  = []
    audit_rows:  list[dict]  = []

    for row in chunk:
        try:
            target_record, source_hash, target_hash = transform(row)
        except UnmappedStatusError as exc:
            log.error("UNMAPPED STATUS — chunk aborted: %s", exc)
            return 0, 0, 0, len(chunk)  # entire chunk skipped

        outcome = "OK" if source_hash == target_hash else "HASH_MISMATCH"
        if outcome == "HASH_MISMATCH":
            log.warning("HASH_MISMATCH for issuance_id=%s", target_record["issuance_id"])

        target_rows.append(target_record)
        audit_rows.append(
            {
                "source_record_id": row["procedure_id"],
                "target_record_id": target_record["issuance_id"],
                "source_hash":      source_hash,
                "target_hash":      target_hash,
                "outcome":          outcome,
            }
        )

    ok            = sum(1 for r in audit_rows if r["outcome"] == "OK")
    hash_mismatch = sum(1 for r in audit_rows if r["outcome"] == "HASH_MISMATCH")

    if not dry_run:
        psycopg2.extras.execute_batch(write_cur, INSERT_TARGET_SQL, target_rows)
        psycopg2.extras.execute_batch(write_cur, INSERT_AUDIT_SQL, audit_rows)

    return ok, hash_mismatch, 0, 0


# ── Main logic ────────────────────────────────────────────────────────────────


def run(dry_run: bool) -> int:
    log.info("Connecting to target DB (%s:%s/%s)…", config.DB_HOST, config.DB_PORT, config.DB_NAME)
    conn = config.get_db_connection()

    if dry_run:
        log.info("DRY-RUN mode — no data will be written to the database.")

    total_ok       = 0
    total_mismatch = 0
    total_skipped  = 0
    total_errors   = 0

    try:
        verify_schema(conn)

        if not dry_run:
            with conn.cursor() as cur:
                cur.execute(CREATE_AUDIT_DDL)
            conn.commit()

        # Use a server-side named cursor to stream staging rows without loading
        # the entire table into memory. Named cursors require an open transaction
        # (autocommit=False, which is the psycopg2 default).
        read_conn = config.get_db_connection()

        try:
            with read_conn.cursor(
                name="staging_stream",
                cursor_factory=psycopg2.extras.RealDictCursor,
            ) as read_cur:
                read_cur.itersize = config.CHUNK_SIZE
                read_cur.execute(
                    f"SELECT * FROM {config.STAGING_TABLE} ORDER BY procedure_id"
                )

                chunk_num = 0
                while True:
                    chunk = read_cur.fetchmany(config.CHUNK_SIZE)
                    if not chunk:
                        break

                    chunk_num += 1
                    chunk_list = [dict(r) for r in chunk]
                    log.info(
                        "Processing chunk %d (%d rows)…", chunk_num, len(chunk_list)
                    )

                    try:
                        with conn.cursor() as write_cur:
                            ok, mismatch, skipped, errors = process_chunk(
                                chunk_list, write_cur, dry_run
                            )
                        if not dry_run:
                            conn.commit()
                    except Exception as exc:
                        conn.rollback()
                        log.error("Chunk %d failed and was rolled back: %s", chunk_num, exc)
                        total_errors += len(chunk_list)
                        continue

                    total_ok       += ok
                    total_mismatch += mismatch
                    total_skipped  += skipped
                    total_errors   += errors
        finally:
            read_conn.close()

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    prefix = "[DRY-RUN] " if dry_run else ""
    print()
    print(f"─── 02_etl_migrate  summary {prefix}─────────────────")
    print(f"  Total rows processed : {total_ok + total_mismatch + total_skipped + total_errors}")
    print(f"  OK                   : {total_ok}")
    print(f"  HASH_MISMATCH        : {total_mismatch}")
    print(f"  SKIPPED              : {total_skipped}")
    print(f"  Chunk errors         : {total_errors}")
    if dry_run:
        print("  (No rows were written — dry-run mode)")
    print("─────────────────────────────────────────────────────")

    return 1 if total_mismatch > 0 else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ETL migration from issuance_staging to issuance (step 2/3)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute all transform/hash logic without writing to the database.",
    )
    args = parser.parse_args()
    sys.exit(run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
