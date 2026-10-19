"""
config.py — All runtime configuration read from environment variables or .env file.
No values are hardcoded. Load a .env file locally with python-dotenv before importing.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            "Check your .env file or shell environment."
        )
    return val


# ── Target database (EUDIStack / AWS replica) ─────────────────────────────────
DB_HOST     = _require("DB_HOST")
DB_PORT     = int(os.environ.get("DB_PORT", "5432"))
DB_NAME     = _require("DB_NAME")
DB_USER     = _require("DB_USER")
DB_PASSWORD = _require("DB_PASSWORD")
# 'require' for AWS RDS (SSL mandatory). Use 'disable' only for local Docker.
DB_SSLMODE  = os.environ.get("DB_SSLMODE", "prefer")

# ── File paths ────────────────────────────────────────────────────────────────
CSV_INPUT_PATH    = os.environ.get("CSV_INPUT_PATH", "")
REPORT_OUTPUT_DIR = os.environ.get("REPORT_OUTPUT_DIR", "./reports/")

# ── Migration constants ───────────────────────────────────────────────────────
CHUNK_SIZE    = 500
STAGING_TABLE = "dome_issuer.issuance_staging"
TARGET_TABLE  = "dome_issuer.issuance"
AUDIT_TABLE   = "dome_issuer.migration_audit"


def get_db_connection():
    """Return a new psycopg2 connection to the target database."""
    import psycopg2

    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        sslmode=DB_SSLMODE,
        connect_timeout=10,
        options="-c statement_timeout=300000",
    )
