#!/usr/bin/env python3
"""
03_reconcile.py — Step 3 of 3.

Reads migration_audit and issuance to produce an auditable reconciliation
report. Exits 0 only when row counts match and there are zero HASH_MISMATCHes.

Usage:
    python 03_reconcile.py
    python 03_reconcile.py --output-dir ./reports/
"""

import argparse
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
import psycopg2
import psycopg2.extras

import config
from status_mapping import STATUS_MAP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SCRIPT_VERSION = "1.0.0"

# ── Helpers ───────────────────────────────────────────────────────────────────


def verify_schema(conn: "psycopg2.connection") -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'dome_issuer'"
        )
        if cur.fetchone() is None:
            log.error(
                "Schema 'dome_issuer' does not exist.\n"
                "Run the Flyway migration before executing this script."
            )
            sys.exit(2)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


# ── Data collection ───────────────────────────────────────────────────────────


def collect_stats(conn: "psycopg2.connection") -> dict:
    stats: dict = {}

    with conn.cursor() as cur:
        # Row counts
        cur.execute(f"SELECT COUNT(*) FROM {config.STAGING_TABLE}")
        stats["staging_count"] = cur.fetchone()[0]

        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM {config.TARGET_TABLE} i
            WHERE i.issuance_id IN (
                SELECT source_record_id FROM {config.AUDIT_TABLE}
            )
            """
        )
        stats["issuance_count"] = cur.fetchone()[0]

        # Outcome breakdown
        cur.execute(
            f"""
            SELECT outcome, COUNT(*) AS n
            FROM {config.AUDIT_TABLE}
            GROUP BY outcome
            """
        )
        outcome_counts: dict[str, int] = {row[0]: row[1] for row in cur.fetchall()}
        stats["ok_count"]        = outcome_counts.get("OK", 0)
        stats["mismatch_count"]  = outcome_counts.get("HASH_MISMATCH", 0)
        stats["skipped_count"]   = outcome_counts.get("SKIPPED", 0)

        # Tampering detection: rows marked OK but whose source_hash ≠ target_hash
        # in migration_audit. Catches direct edits to target_hash in the audit table.
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM {config.AUDIT_TABLE}
            WHERE outcome = 'OK'
              AND source_hash IS DISTINCT FROM target_hash
            """
        )
        stats["tampered_count"] = cur.fetchone()[0]

        # Aggregate hash: SHA-256 of the concatenation (sorted by source_record_id)
        # of all target_hash values where outcome='OK'.
        cur.execute(
            f"""
            SELECT target_hash
            FROM {config.AUDIT_TABLE}
            WHERE outcome = 'OK'
            ORDER BY source_record_id ASC
            """
        )
        ok_hashes = [row[0] for row in cur.fetchall() if row[0]]
        aggregate_input = "".join(ok_hashes).encode("utf-8")
        stats["aggregate_hash"] = hashlib.sha256(aggregate_input).hexdigest()

        # Transformation counts: join staging → audit → issuance to get
        # (original_status, mapped_status, count).
        cur.execute(
            f"""
            SELECT
                s.credential_status  AS source_status,
                i.credential_status  AS target_status,
                COUNT(*)             AS n
            FROM {config.AUDIT_TABLE} ma
            JOIN {config.STAGING_TABLE} s
                ON ma.source_record_id = s.procedure_id
            JOIN {config.TARGET_TABLE} i
                ON ma.target_record_id = i.issuance_id
            WHERE ma.outcome = 'OK'
            GROUP BY s.credential_status, i.credential_status
            ORDER BY n DESC
            """
        )
        stats["transformations"] = [
            {"source": row[0], "target": row[1], "n": row[2]}
            for row in cur.fetchall()
        ]

        # HASH_MISMATCH records
        cur.execute(
            f"""
            SELECT source_record_id
            FROM {config.AUDIT_TABLE}
            WHERE outcome = 'HASH_MISMATCH'
            ORDER BY source_record_id
            """
        )
        stats["mismatch_ids"] = [str(row[0]) for row in cur.fetchall()]

    return stats


# ── Report generation ─────────────────────────────────────────────────────────


def build_report(stats: dict, generated_at: datetime, failures: list[str]) -> str:
    """Build the Markdown reconciliation report."""
    diff          = stats["staging_count"] - stats["issuance_count"]
    ok_icon       = lambda v: "✅" if v == 0 else "❌"
    passed        = not failures

    lines: list[str] = []
    w = lines.append

    w("# Migration Report — DOME Issuer")
    w("")
    w(f"**Generated (UTC):** {generated_at.strftime('%Y-%m-%d %H:%M:%S')}  ")
    w(f"**Script version:** {SCRIPT_VERSION}")
    w("")
    w("---")

    # ── COUNTS ────────────────────────────────────────────────────────────────
    w("")
    w("## Row counts")
    w("")
    w("| Metric | Value |")
    w("|--------|------:|")
    w(f"| Staging rows (`issuance_staging`) | {stats['staging_count']} |")
    w(f"| Migrated rows (`issuance`)        | {stats['issuance_count']} |")
    w(f"| Difference                        | {diff} {ok_icon(diff)} |")
    w("")

    # ── RESULT ────────────────────────────────────────────────────────────────
    w("## Integrity checks")
    w("")
    w("| Check | Value |")
    w("|-------|------:|")
    w(f"| HASH_MISMATCH   | {stats['mismatch_count']} {ok_icon(stats['mismatch_count'])} |")
    w(f"| SKIPPED         | {stats['skipped_count']} {ok_icon(stats['skipped_count'])} |")
    w(f"| Tampered hashes | {stats['tampered_count']} {ok_icon(stats['tampered_count'])} |")
    w("")

    # ── AGGREGATE HASH ────────────────────────────────────────────────────────
    w("## Aggregate verification hash")
    w("")
    w("> SHA-256 of all `target_hash` values (outcome=OK, ordered by `source_record_id` ASC).")
    w("")
    w("```")
    w(stats["aggregate_hash"])
    w("```")
    w("")

    # ── TRANSFORMATIONS ───────────────────────────────────────────────────────
    w("## Status transformations")
    w("")
    w("| Source status | → | Target status | Count |")
    w("|---------------|:-:|---------------|------:|")

    transformation_index: dict[tuple[str, str], int] = {
        (t["source"], t["target"]): t["n"] for t in stats["transformations"]
    }
    for src, tgt in STATUS_MAP.items():
        n = transformation_index.get((src, tgt), 0)
        w(f"| `{src}` | → | `{tgt}` | {n} |")

    # Warn about any pair observed in the data but absent from STATUS_MAP.
    mapped_pairs = set(STATUS_MAP.items())
    extra = [t for t in stats["transformations"] if (t["source"], t["target"]) not in mapped_pairs]
    if extra:
        w("")
        w(">  **!Unmapped pairs observed in data (not in STATUS_MAP):**")
        w("")
        w("| Source status | → | Target status | Count |")
        w("|---------------|:-:|---------------|------:|")
        for t in extra:
            w(f"| `{t['source']}` | → | `{t['target']}` | {t['n']} |")
    w("")

    # ── HASH_MISMATCH RECORDS ─────────────────────────────────────────────────
    w("## HASH_MISMATCH records")
    w("")
    if stats["mismatch_ids"]:
        w("| issuance_id |")
        w("|-------------|")
        for uid in stats["mismatch_ids"]:
            w(f"| `{uid}` |")
    else:
        w("_(none)_")
    w("")

    # ── OUTCOME ───────────────────────────────────────────────────────────────
    w("---")
    w("")
    if passed:
        w("##  RECONCILIATION PASSED")
        w("")
        w("All counts match and no integrity issues detected.")
    else:
        w("## !RECONCILIATION FAILED!")
        w("")
        for msg in failures:
            w(f"- {msg}")
    w("")

    return "\n".join(lines)


# ── Main logic ────────────────────────────────────────────────────────────────


def run(output_dir: str) -> int:
    log.info("Connecting to target DB (%s:%s/%s)…", config.DB_HOST, config.DB_PORT, config.DB_NAME)
    conn = config.get_db_connection()

    try:
        verify_schema(conn)
        log.info("Collecting reconciliation data…")
        stats = collect_stats(conn)
    finally:
        conn.close()

    generated_at = datetime.now(tz=timezone.utc)

    # Compute failures first so the report can embed the outcome section.
    diff     = stats["staging_count"] - stats["issuance_count"]
    failures: list[str] = []
    if diff != 0:
        failures.append(
            f"Row count mismatch: {stats['staging_count']} staging rows "
            f"vs {stats['issuance_count']} issuance rows (diff={diff})"
        )
    if stats["mismatch_count"] > 0:
        failures.append(
            f"{stats['mismatch_count']} HASH_MISMATCH record(s) found — "
            f"see the report for affected issuance_ids"
        )
    if stats["tampered_count"] > 0:
        failures.append(
            f"{stats['tampered_count']} audit record(s) with outcome='OK' have "
            "source_hash ≠ target_hash — possible tampering of migration_audit"
        )

    report_md = build_report(stats, generated_at, failures)

    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = generated_at.strftime("%Y%m%d_%H%M%S")
    report_name   = f"migration_report_{timestamp_str}.md"
    report_path   = os.path.join(output_dir, report_name)
    sha256_path   = report_path + ".sha256"

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    log.info("Report written: %s", report_path)

    file_hash = sha256_file(report_path)
    with open(sha256_path, "w", encoding="utf-8") as fh:
        fh.write(f"{file_hash}  {report_name}\n")
    log.info("SHA-256 written: %s", sha256_path)

    # ── Console summary ───────────────────────────────────────────────────────
    diff = stats["staging_count"] - stats["issuance_count"]
    print()
    print("─── 03_reconcile  summary ───────────────────────────")
    print(f"  Staging rows      : {stats['staging_count']}")
    print(f"  Issuance rows     : {stats['issuance_count']}")
    print(f"  Difference        : {diff}")
    print(f"  HASH_MISMATCH     : {stats['mismatch_count']}")
    print(f"  SKIPPED           : {stats['skipped_count']}")
    print(f"  Tampered hashes   : {stats['tampered_count']}")
    print(f"  Aggregate hash    : {stats['aggregate_hash']}")
    print(f"  Report            : {report_path}")
    print(f"  Report SHA-256    : {file_hash}")
    print("─────────────────────────────────────────────────────")

    # ── Exit code ─────────────────────────────────────────────────────────────

    if failures:
        print()
        print("RECONCILIATION FAILED:")
        for msg in failures:
            print(f"  • {msg}")
        return 1

    print()
    print("RECONCILIATION PASSED — migration looks good.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reconcile staging vs issuance and emit an auditable CSV report (step 3/3)."
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=config.REPORT_OUTPUT_DIR,
        help="Directory where the CSV report will be saved (default: ./reports/).",
    )
    args = parser.parse_args()
    sys.exit(run(output_dir=args.output_dir))


if __name__ == "__main__":
    main()
