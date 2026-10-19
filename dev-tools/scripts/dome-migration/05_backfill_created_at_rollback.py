#!/usr/bin/env python3
"""
05_backfill_created_at_rollback.py — Rollback of the created_at backfill (05).

Sets issuance.created_at back to NULL for exactly the rows that a real run of
05_backfill_created_at.py wrote, as listed in its report CSV (outcome = OK).
04_rollback.py does NOT cover this step: it deletes the migrated rows instead.

A row is only reverted if its created_at still holds the exact value the
backfill wrote. Rows changed since then, already NULL or missing are left
untouched and listed in the summary for review.

Runs in a single transaction: if the number of reverted rows differs from the
plan (concurrent change), nothing is written.

The report of a real run is the only input: dry-run reports are rejected, since
they list what would have been written, not what was. Keep that CSV safe —
reports/ is git-ignored and only exists on the machine that ran the backfill.

Usage:
    python 05_backfill_created_at_rollback.py --report reports/<real-run>.csv --dry-run
    python 05_backfill_created_at_rollback.py --report reports/<real-run>.csv
    python 05_backfill_created_at_rollback.py --report reports/<real-run>.csv --yes
    python 05_backfill_created_at_rollback.py --report reports/<real-run>.csv --schema other_tenant_schema
"""

import argparse
import csv
import logging
import os
import re
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

DEFAULT_SCHEMA = "dome_issuer"
OUTCOME_OK     = "OK"

STATE_MATCH        = "MATCH"         # still holds the value the backfill wrote → reverted
STATE_CHANGED      = "CHANGED"       # holds another value → left untouched
STATE_ALREADY_NULL = "ALREADY_NULL"  # already NULL → nothing to do
STATE_NOT_FOUND    = "NOT_FOUND"     # issuance_id no longer exists

_SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
# Report name written by 05: backfill_created_at_<schema>_<YYYYMMDD>_<HHMMSS>[_dry-run].csv
_REPORT_RE = re.compile(r"^backfill_created_at_(?P<schema>[a-z_][a-z0-9_]*)_\d{8}_\d{6}(?P<dry>_dry-run)?\.csv$")

# ── Report ────────────────────────────────────────────────────────────────────


def check_report_name(path: str, schema: str) -> None:
    """Reject dry-run reports and reports produced for another schema."""
    match = _REPORT_RE.match(os.path.basename(path))
    if match is None:
        log.error("Unexpected report name: %s (expected the CSV written by 05_backfill_created_at.py).", path)
        sys.exit(2)
    if match.group("dry"):
        log.error("%s is a dry-run report: it lists what would have been written, not what was.", path)
        sys.exit(2)
    if match.group("schema") != schema:
        log.error(
            "Report was produced for schema '%s' but --schema is '%s'.", match.group("schema"), schema
        )
        sys.exit(2)


def load_written_rows(path: str) -> list[tuple[str, datetime]]:
    """Return (issuance_id, created_at written) for every OK row of the report."""
    rows: list[tuple[str, datetime]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["outcome"] == OUTCOME_OK:
                rows.append((row["issuance_id"], datetime.fromisoformat(row["created_at"])))
    return rows


def classify(written: list[tuple[str, datetime]], current: dict[str, datetime | None]) -> dict[str, list[str]]:
    """Group issuance_ids by their current state against the value the backfill wrote."""
    states: dict[str, list[str]] = {
        STATE_MATCH: [], STATE_CHANGED: [], STATE_ALREADY_NULL: [], STATE_NOT_FOUND: [],
    }
    for issuance_id, created_at in written:
        if issuance_id not in current:
            states[STATE_NOT_FOUND].append(issuance_id)
        elif current[issuance_id] is None:
            states[STATE_ALREADY_NULL].append(issuance_id)
        elif current[issuance_id] == created_at:
            states[STATE_MATCH].append(issuance_id)
        else:
            states[STATE_CHANGED].append(issuance_id)
    return states


# ── Main logic ────────────────────────────────────────────────────────────────


def run(report: str, schema: str, dry_run: bool, yes: bool) -> int:
    # Imported here so the report helpers can be used without a .env.
    from psycopg2 import sql

    import config

    written = load_written_rows(report)
    log.info("Report %s: %d rows written by the backfill.", report, len(written))
    if not written:
        print("The report has no OK rows — nothing to revert.")
        return 0

    log.info("Connecting to target DB (%s:%s/%s)…", config.DB_HOST, config.DB_PORT, config.DB_NAME)
    if dry_run:
        log.info("DRY-RUN mode — no data will be written to the database.")

    table      = sql.Identifier(schema, "issuance")
    select_sql = sql.SQL(
        "SELECT issuance_id::text, created_at FROM {} WHERE issuance_id = ANY(%s::uuid[])"
    ).format(table)
    # Re-checks the written value inside the UPDATE, so a row changed after the plan is never reverted.
    update_sql = sql.SQL(
        "UPDATE {} AS i SET created_at = NULL "
        "FROM unnest(%s::uuid[], %s::timestamptz[]) AS r(issuance_id, created_at) "
        "WHERE i.issuance_id = r.issuance_id AND i.created_at = r.created_at"
    ).format(table)

    conn = config.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = %s AND table_name = 'issuance'",
                (schema,),
            )
            if cur.fetchone() is None:
                log.error("Table '%s.issuance' does not exist in the target database.", schema)
                return 2

            cur.execute(select_sql, ([issuance_id for issuance_id, _ in written],))
            current = {issuance_id: created_at for issuance_id, created_at in cur.fetchall()}

        states  = classify(written, current)
        matched = set(states[STATE_MATCH])
        to_null = [(issuance_id, created_at) for issuance_id, created_at in written if issuance_id in matched]
        review  = len(states[STATE_CHANGED]) + len(states[STATE_NOT_FOUND])

        prefix = "[DRY-RUN] " if dry_run else ""
        print()
        print(f"─── 05_backfill_created_at_rollback  plan {prefix}──────")
        print(f"  Schema                          : {schema}")
        print(f"  Rows written by the backfill    : {len(written)}")
        print(f"    to revert (value unchanged)   : {len(states[STATE_MATCH])}")
        print(f"    already NULL (nothing to do)  : {len(states[STATE_ALREADY_NULL])}")
        print(f"    changed since (left as is)    : {len(states[STATE_CHANGED])}")
        print(f"    not found (left as is)        : {len(states[STATE_NOT_FOUND])}")
        print("─────────────────────────────────────────────────────")
        for state in (STATE_CHANGED, STATE_NOT_FOUND):
            for issuance_id in states[state]:
                log.warning("%s issuance_id=%s", state, issuance_id)

        if not to_null:
            print()
            print("Nothing to revert.")
            return 1 if review else 0

        if dry_run:
            print()
            print("[DRY-RUN] Nothing was written.")
            return 1 if review else 0

        if not yes:
            print()
            resp = input(
                f"This sets created_at back to NULL on {len(to_null)} rows of {schema}.issuance.\n"
                "Type 'ROLLBACK' to confirm: "
            ).strip()
            if resp != "ROLLBACK":
                print("Cancelled.")
                return 1

        with conn.cursor() as cur:
            cur.execute(update_sql, (
                [issuance_id for issuance_id, _ in to_null],
                [created_at for _, created_at in to_null],
            ))
            reverted = cur.rowcount
        if reverted != len(to_null):
            conn.rollback()
            log.error(
                "Reverted %d rows but the plan had %d (concurrent change?) — transaction rolled back, "
                "nothing was written. Re-run to recompute the plan.", reverted, len(to_null)
            )
            return 1
        conn.commit()

        print()
        print("─── 05_backfill_created_at_rollback  result ─────────")
        print(f"  Rows set back to NULL           : {reverted}")
        print(f"  Rows left for review            : {review}")
        print("─────────────────────────────────────────────────────")
        return 1 if review else 0

    except Exception:
        conn.rollback()
        log.error("Error during the rollback — transaction rolled back, nothing was written.")
        raise
    finally:
        conn.close()


def main() -> None:
    # Windows uses cp1252 when output is redirected (e.g. `> run.log`); the summary's
    # box-drawing characters would otherwise abort the run after the work is done.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(
        description="Revert the created_at backfill (05) using the report of its real run."
    )
    parser.add_argument(
        "--report",
        required=True,
        help="CSV written by the real (non dry-run) run of 05_backfill_created_at.py.",
    )
    parser.add_argument(
        "--schema",
        default=DEFAULT_SCHEMA,
        help=f"Tenant schema that holds the issuance table (default: {DEFAULT_SCHEMA}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be reverted without writing to the database.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation.",
    )
    args = parser.parse_args()

    if args.dry_run and args.yes:
        log.error("--dry-run and --yes are mutually exclusive.")
        sys.exit(1)
    if not _SCHEMA_RE.match(args.schema):
        log.error("Invalid schema name: %r", args.schema)
        sys.exit(2)
    if not os.path.isfile(args.report):
        log.error("Report not found: %s", args.report)
        sys.exit(2)
    check_report_name(args.report, args.schema)

    sys.exit(run(report=args.report, schema=args.schema, dry_run=args.dry_run, yes=args.yes))


if __name__ == "__main__":
    main()
