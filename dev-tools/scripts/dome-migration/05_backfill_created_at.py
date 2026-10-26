#!/usr/bin/env python3
"""
05_backfill_created_at.py — Post-migration step.

Fills issuance.created_at for rows where it is NULL, using the issuance date
stored in the credential JSON (credential_data_set). Two causes leave the
column empty:
  - v2 credentials issued before the V7 migration (2025-11-05), which added
    created_at without backfilling it; the ETL (02) copies that NULL as is.
  - credentials issued by v2 >= 2.2.11 or by v3 before EUD-225 (2026-08-18):
    the entity was inserted with a pre-assigned id and no @Version, so Spring
    Data auditing treated it as "not new" and never set @CreatedDate.

Date sources, first match wins:
  1. validFrom             (VCDM 2.0, root)
  2. vc.validFrom          (VCDM 2.0 nested in JWT-style payload)
  3. issuanceDate          (VCDM 1.1, root)
  4. vc.issuanceDate       (VCDM 1.1 nested)

Rows whose JSON is invalid or carries no parseable date are NOT touched: they
are reported as SKIPPED so they can be reviewed by hand. Nothing is invented.
Neither are rows whose date is later than their own updated_at, which is
impossible for a creation date (SKIPPED_AFTER_UPDATED_AT; the candidate date
is kept in the report for review).

For LabelCredential / VerifiableCertification (and early LEARCredentialMachine)
validFrom came from the issuance request, so it may not be the issuance moment.
Rows of any type whose date looks implausible ARE updated, but flagged in the
report and the summary for review:
  - FUTURE             date later than now (only reachable when updated_at is
                       NULL; otherwise the row is SKIPPED_AFTER_UPDATED_AT)
  - MIDNIGHT_UTC       exactly 00:00:00.000 UTC — typical of a hand-set date
  - SHARED_TIMESTAMP   same exact date on >= SHARED_TIMESTAMP_MIN rows
Warnings never change what is written nor the exit code.

Works the same on SBX (data already migrated) and PRD (run after 02 + 03):
only the .env changes. Idempotent: only rows with created_at IS NULL are read,
and the UPDATE re-checks that condition, so re-runs never overwrite a value.
To undo a real run, use 05_backfill_created_at_rollback.py with its report.

Only issuance_id and the date source are logged — credential_data_set is PII
and is never written to the log or the report.

Usage:
    python 05_backfill_created_at.py --dry-run
    python 05_backfill_created_at.py
    python 05_backfill_created_at.py --schema other_tenant_schema --dry-run
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

DEFAULT_SCHEMA = "dome_issuer"

# (label, path inside the credential JSON), in priority order.
DATE_SOURCES = [
    ("validFrom",         ("validFrom",)),
    ("vc.validFrom",      ("vc", "validFrom")),
    ("issuanceDate",      ("issuanceDate",)),
    ("vc.issuanceDate",   ("vc", "issuanceDate")),
]

OUTCOME_OK           = "OK"
OUTCOME_INVALID_JSON = "SKIPPED_INVALID_JSON"
OUTCOME_NO_DATE      = "SKIPPED_NO_DATE"
OUTCOME_BAD_DATE     = "SKIPPED_UNPARSEABLE_DATE"
OUTCOME_AFTER_UPDATED = "SKIPPED_AFTER_UPDATED_AT"

WARN_FUTURE        = "FUTURE"
WARN_MIDNIGHT      = "MIDNIGHT_UTC"
WARN_SHARED        = "SHARED_TIMESTAMP"
# Real issuance timestamps carry (micro)seconds; several identical ones mean a
# date copied from the request rather than the moment of issuance.
SHARED_TIMESTAMP_MIN = 3

_SCHEMA_RE   = re.compile(r"^[a-z_][a-z0-9_]*$")
# Java Instant can emit up to 9 fractional digits; Python accepts at most 6.
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")

# ── Extraction ────────────────────────────────────────────────────────────────


def parse_iso_datetime(value: str) -> datetime | None:
    """
    Parse an ISO-8601 timestamp as found in credentials
    (e.g. 2025-05-05T18:28:25Z, 2025-05-05T18:28:25.123456789Z, ...+02:00).
    A timestamp without offset is taken as UTC (Instant.toString() is UTC).
    Returns None when the value cannot be parsed.
    """
    text = _FRACTION_RE.sub(r"\1", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _get_path(document: dict, path: tuple[str, ...]) -> object:
    node: object = document
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def extract_created_at(credential_data_set: str | None) -> tuple[str, str | None, datetime | None]:
    """
    Returns (outcome, source_label, created_at).
    source_label is set when a candidate date was found (even if unparseable).
    """
    try:
        document = json.loads(credential_data_set or "")
    except (json.JSONDecodeError, TypeError):
        return OUTCOME_INVALID_JSON, None, None
    if not isinstance(document, dict):
        return OUTCOME_INVALID_JSON, None, None

    for label, path in DATE_SOURCES:
        raw = _get_path(document, path)
        if isinstance(raw, str) and raw.strip():
            parsed = parse_iso_datetime(raw)
            if parsed is None:
                return OUTCOME_BAD_DATE, label, None
            return OUTCOME_OK, label, parsed

    return OUTCOME_NO_DATE, None, None


def resolve_created_at(
    credential_data_set: str | None, updated_at: datetime | None
) -> tuple[str, str | None, datetime | None]:
    """
    extract_created_at() plus the consistency check against the row itself:
    a creation date later than updated_at is impossible, so the row is skipped.
    The candidate date is still returned so it shows up in the report.
    """
    outcome, source, created_at = extract_created_at(credential_data_set)
    if outcome == OUTCOME_OK and updated_at is not None and created_at > updated_at:
        return OUTCOME_AFTER_UPDATED, source, created_at
    return outcome, source, created_at


def row_warnings(created_at: datetime, now: datetime) -> list[str]:
    """Per-row plausibility checks. SHARED_TIMESTAMP needs every row and is added later."""
    warnings = []
    if created_at > now:
        warnings.append(WARN_FUTURE)
    utc = created_at.astimezone(timezone.utc)
    if (utc.hour, utc.minute, utc.second, utc.microsecond) == (0, 0, 0, 0):
        warnings.append(WARN_MIDNIGHT)
    return warnings


def add_shared_timestamp_warnings(report_rows: list[dict]) -> None:
    # Only rows that are actually written: skipped rows are reviewed anyway.
    written = [row for row in report_rows if row["outcome"] == OUTCOME_OK]
    occurrences: dict[str, int] = {}
    for row in written:
        occurrences[row["created_at"]] = occurrences.get(row["created_at"], 0) + 1
    for row in written:
        if occurrences[row["created_at"]] >= SHARED_TIMESTAMP_MIN:
            row["warnings"].append(WARN_SHARED)


# ── Database ──────────────────────────────────────────────────────────────────


def verify_table(conn, schema: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name = 'issuance'",
            (schema,),
        )
        if cur.fetchone() is None:
            log.error("Table '%s.issuance' does not exist in the target database.", schema)
            sys.exit(2)


def write_report(rows: list[dict], schema: str, dry_run: bool, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp  = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = "_dry-run" if dry_run else ""
    path   = os.path.join(output_dir, f"backfill_created_at_{schema}_{stamp}{suffix}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["issuance_id", "credential_type", "outcome", "source", "created_at", "warnings"]
        )
        writer.writeheader()
        writer.writerows({**row, "warnings": "|".join(row["warnings"])} for row in rows)
    return path


# ── Main logic ────────────────────────────────────────────────────────────────


def run(schema: str, dry_run: bool) -> int:
    # Imported here so the extraction helpers can be used without a .env.
    import psycopg2
    import psycopg2.extras
    from psycopg2 import sql

    import config

    log.info("Connecting to target DB (%s:%s/%s)…", config.DB_HOST, config.DB_PORT, config.DB_NAME)
    if dry_run:
        log.info("DRY-RUN mode — no data will be written to the database.")

    table      = sql.Identifier(schema, "issuance")
    select_sql = sql.SQL(
        "SELECT issuance_id, credential_type, credential_data_set, updated_at FROM {} "
        "WHERE created_at IS NULL ORDER BY issuance_id"
    ).format(table)
    update_sql = sql.SQL(
        "UPDATE {} SET created_at = %(created_at)s "
        "WHERE issuance_id = %(issuance_id)s AND created_at IS NULL"
    ).format(table)

    report_rows: list[dict] = []
    counts: dict[str, int]  = {}
    updated = 0
    now     = datetime.now(tz=timezone.utc)

    conn = config.get_db_connection()
    try:
        verify_table(conn, schema)
        read_conn = config.get_db_connection()
        try:
            with read_conn.cursor(name="backfill_stream") as read_cur:
                read_cur.itersize = config.CHUNK_SIZE
                read_cur.execute(select_sql)

                chunk_num = 0
                while True:
                    chunk = read_cur.fetchmany(config.CHUNK_SIZE)
                    if not chunk:
                        break
                    chunk_num += 1

                    updates: list[dict] = []
                    for issuance_id, credential_type, credential_data_set, updated_at in chunk:
                        outcome, source, created_at = resolve_created_at(credential_data_set, updated_at)
                        key = f"{outcome} ({source})" if outcome == OUTCOME_OK else outcome
                        counts[key] = counts.get(key, 0) + 1
                        report_rows.append({
                            "issuance_id":     str(issuance_id),
                            "credential_type": credential_type or "",
                            "outcome":         outcome,
                            "source":          source or "",
                            # Normalised to UTC so SHARED_TIMESTAMP compares instants, not offsets.
                            "created_at":      created_at.astimezone(timezone.utc).isoformat() if created_at else "",
                            "warnings":        row_warnings(created_at, now) if outcome == OUTCOME_OK else [],
                        })
                        if outcome == OUTCOME_OK:
                            updates.append({"issuance_id": issuance_id, "created_at": created_at})
                        else:
                            log.warning("%s issuance_id=%s source=%s", outcome, issuance_id, source or "-")

                    log.info("Chunk %d: %d rows read, %d to update", chunk_num, len(chunk), len(updates))

                    if not dry_run and updates:
                        try:
                            with conn.cursor() as write_cur:
                                psycopg2.extras.execute_batch(write_cur, update_sql, updates)
                            conn.commit()
                            updated += len(updates)
                        except Exception:
                            conn.rollback()
                            log.exception("Chunk %d failed and was rolled back", chunk_num)
                            raise
        finally:
            read_conn.close()
    finally:
        conn.close()

    add_shared_timestamp_warnings(report_rows)
    report_path = write_report(report_rows, schema, dry_run, config.REPORT_OUTPUT_DIR)

    skipped = sum(n for k, n in counts.items() if not k.startswith(OUTCOME_OK))

    warned_rows = [row for row in report_rows if row["warnings"]]
    warn_counts:  dict[str, int] = {}
    warn_groups:  dict[tuple[str, str, str], int] = {}
    for row in warned_rows:
        for warning in row["warnings"]:
            warn_counts[warning] = warn_counts.get(warning, 0) + 1
        group = (row["credential_type"], row["created_at"], ", ".join(row["warnings"]))
        warn_groups[group] = warn_groups.get(group, 0) + 1
    prefix  = "[DRY-RUN] " if dry_run else ""
    print()
    print(f"─── 05_backfill_created_at  summary {prefix}──────────")
    print(f"  Schema                     : {schema}")
    print(f"  Rows with created_at NULL  : {len(report_rows)}")
    for key in sorted(counts):
        print(f"    {key:<36}: {counts[key]}")
    print(f"  Rows updated               : {updated}")
    print(f"  Rows skipped (review)      : {skipped}")
    print(f"  Rows with warnings (review): {len(warned_rows)}  (updated anyway; see 'warnings' in the report)")
    for warning in sorted(warn_counts):
        print(f"    {warning:<36}: {warn_counts[warning]}")
    if warn_groups:
        print()
        print(f"    {'credential_type':<30} {'rows':>5}  {'created_at (UTC)':<34} warnings")
        for (credential_type, created_at, warnings), n in sorted(
            warn_groups.items(), key=lambda item: (-item[1], item[0])
        ):
            print(f"    {credential_type:<30} {n:>5}  {created_at:<34} {warnings}")
        print()
    print(f"  Report                     : {report_path}")
    if dry_run:
        print("  (No rows were written — dry-run mode)")
    print("─────────────────────────────────────────────────────")

    return 1 if skipped > 0 else 0


def main() -> None:
    # Windows uses cp1252 when output is redirected (e.g. `> run.log`); the summary's
    # box-drawing characters would otherwise abort the run after the work is done.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(
        description="Backfill issuance.created_at from the credential JSON (post-migration step)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and report the values without writing to the database.",
    )
    parser.add_argument(
        "--schema",
        default=DEFAULT_SCHEMA,
        help=f"Tenant schema that holds the issuance table (default: {DEFAULT_SCHEMA}).",
    )
    args = parser.parse_args()

    if not _SCHEMA_RE.match(args.schema):
        log.error("Invalid schema name: %r", args.schema)
        sys.exit(2)

    sys.exit(run(schema=args.schema, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
