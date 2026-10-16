#!/usr/bin/env python3
"""
04_rollback.py — Rollback de la migración ETL.

Lee los source_record_id de dome_issuer.migration_audit (los IDs exactos que
se insertaron en dome_issuer.issuance) y los elimina. Opera dentro de una
única transacción: si algo falla, no se borra nada.

Uso:
    python 04_rollback.py --dry-run          # muestra qué se borraría
    python 04_rollback.py                    # pide confirmación interactiva
    python 04_rollback.py --yes              # sin confirmación (CI / scripts)
    python 04_rollback.py --yes --staging    # borra también issuance_staging
"""

import argparse
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

# ── Queries ───────────────────────────────────────────────────────────────────

COUNT_AUDIT_SQL = f"SELECT COUNT(*) FROM {config.AUDIT_TABLE}"

COUNT_ISSUANCE_MIGRATED_SQL = f"""
    SELECT COUNT(*)
    FROM {config.TARGET_TABLE}
    WHERE issuance_id IN (
        SELECT source_record_id FROM {config.AUDIT_TABLE}
    )
"""

DELETE_ISSUANCE_SQL = f"""
    DELETE FROM {config.TARGET_TABLE}
    WHERE issuance_id IN (
        SELECT source_record_id FROM {config.AUDIT_TABLE}
    )
"""

TRUNCATE_AUDIT_SQL   = f"TRUNCATE TABLE {config.AUDIT_TABLE}"
TRUNCATE_STAGING_SQL = f"TRUNCATE TABLE {config.STAGING_TABLE}"

# ── Helpers ───────────────────────────────────────────────────────────────────


def verify_schema(conn: "psycopg2.connection") -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'dome_issuer'"
        )
        if cur.fetchone() is None:
            log.error("Schema 'dome_issuer' no existe en la BD destino.")
            sys.exit(2)


def collect_counts(conn: "psycopg2.connection") -> tuple[int, int]:
    """Devuelve (audit_rows, issuance_migrated_rows)."""
    with conn.cursor() as cur:
        cur.execute(COUNT_AUDIT_SQL)
        audit_count = cur.fetchone()[0]

        cur.execute(COUNT_ISSUANCE_MIGRATED_SQL)
        issuance_count = cur.fetchone()[0]

    return audit_count, issuance_count


# ── Main logic ────────────────────────────────────────────────────────────────


def run(dry_run: bool, yes: bool, clear_staging: bool) -> int:
    log.info(
        "Conectando a BD destino (%s:%s/%s)…", config.DB_HOST, config.DB_PORT, config.DB_NAME
    )
    conn = config.get_db_connection()

    try:
        verify_schema(conn)

        audit_count, issuance_count = collect_counts(conn)

        print()
        print("─── 04_rollback  plan ───────────────────────────────")
        print(f"  Filas en migration_audit          : {audit_count}")
        print(f"  Filas en issuance (a eliminar)    : {issuance_count}")
        print(f"  Limpiar issuance_staging          : {'sí' if clear_staging else 'no'}")
        print("─────────────────────────────────────────────────────")

        if audit_count == 0:
            print()
            print("migration_audit está vacío — nada que revertir.")
            return 0

        if dry_run:
            print()
            print("[DRY-RUN] No se ha borrado nada.")
            return 0

        if not yes:
            print()
            resp = input(
                f"!Esto eliminará {issuance_count} filas de issuance y vaciará! "
                f"migration_audit{'  + issuance_staging' if clear_staging else ''}.\n"
                "Escribe 'ROLLBACK' para confirmar: "
            ).strip()
            if resp != "ROLLBACK":
                print("Operación cancelada.")
                return 1

        log.info("Iniciando transacción de rollback…")
        with conn.cursor() as cur:
            cur.execute(DELETE_ISSUANCE_SQL)
            deleted_issuance = cur.rowcount
            log.info("Eliminadas %d filas de %s.", deleted_issuance, config.TARGET_TABLE)

            cur.execute(TRUNCATE_AUDIT_SQL)
            log.info("Vaciada tabla %s.", config.AUDIT_TABLE)

            if clear_staging:
                cur.execute(TRUNCATE_STAGING_SQL)
                log.info("Vaciada tabla %s.", config.STAGING_TABLE)

        conn.commit()

        # Verificación post-rollback
        audit_after, issuance_after = collect_counts(conn)

        print()
        print("─── 04_rollback  resultado ──────────────────────────")
        print(f"  Filas eliminadas de issuance      : {deleted_issuance}")
        print(f"  Filas restantes en issuance       : {issuance_after}")
        print(f"  Filas restantes en migration_audit: {audit_after}")
        if clear_staging:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {config.STAGING_TABLE}")
                staging_after = cur.fetchone()[0]
            print(f"  Filas restantes en staging        : {staging_after}")
        print("─────────────────────────────────────────────────────")

        if audit_after != 0 or issuance_after != 0:
            log.error(
                "Post-rollback: quedan filas inesperadas. Revisa manualmente."
            )
            return 1

        print()
        print("Rollback completado. Puedes volver a ejecutar 01 → 02 → 03.")
        return 0

    except Exception:
        conn.rollback()
        log.error("Error durante el rollback — transacción revertida, BD sin cambios.")
        raise
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rollback de la migración ETL DOME (paso 4/4 — opcional)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra qué se borraría sin ejecutar ningún DELETE.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Salta la confirmación interactiva (para uso en scripts).",
    )
    parser.add_argument(
        "--staging",
        action="store_true",
        help="Vacía también dome_issuer.issuance_staging además de issuance y migration_audit.",
    )
    args = parser.parse_args()

    if args.dry_run and args.yes:
        log.error("--dry-run y --yes son incompatibles.")
        sys.exit(1)

    sys.exit(run(dry_run=args.dry_run, yes=args.yes, clear_staging=args.staging))


if __name__ == "__main__":
    main()
