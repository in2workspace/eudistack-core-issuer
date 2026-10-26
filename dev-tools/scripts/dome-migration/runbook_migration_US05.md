# RUNBOOK — Migración ETL Credenciales DOME

## `issuer.credential_procedure` → `dome_issuer.issuance`

| Campo | Valor |
|---|---|
| **Tenant** | DOME |
| **Sistema origen** | `issuer.credential_procedure` — IONOS Postgres · schema `issuer` · base `identity` |
| **Sistema destino** | `dome_issuer.issuance` — EUDIStack / AWS RDS |
| **Volumen PRD** | 1 224 registros |
| **Revisión** | 1.3 · 2026-10-16 — añadido rollback del paso 4 (`05_backfill_created_at_rollback.py`) · 1.2 · 2026-10-15 — una fecha posterior a `updated_at` deja de ser aviso y omite la fila (`SKIPPED_AFTER_UPDATED_AT`) · 1.1 · 2026-10-14 — añadido paso 4 (backfill de `created_at`) |

---

## 1. Contexto

La base de datos legacy `identity` (IONOS) almacena las credenciales del tenant DOME en `issuer.credential_procedure`. EUDIStack v3 introduce un modelo de issuance reestructurado en `dome_issuer.issuance`. Esta migración traslada los registros al nuevo schema mediante tres scripts Python que deben ejecutarse en orden.

Los scripts operan sobre un CSV extraído de la fuente (lectura única, sin acceso directo a la BD origen). El destino recibe los datos en dos fases — staging → issuance — con reconciliación auditable al final.

```
IONOS (origen)                CSV          Destino (AWS)
issuer.credential_procedure  ──────►  [01] staging
                                       [02] issuance
                                       [03] reconciliación
                                       [05] backfill created_at
```

**Principios de diseño:**
- Idempotente — re-ejecutable sin duplicar datos (`ON CONFLICT DO NOTHING`).
- Sin acceso directo a la BD origen — sólo lectura del CSV ya extraído.
- `credential_decoded` y `credential_encoded` nunca se loguean (PII + material criptográfico).

---

## 2. Archivos del proceso

| Archivo | Rol |
|---|---|
| `config.py` | Lee toda la configuración desde variables de entorno / `.env` |
| `status_mapping.py` | Mapeo canónico `credential_status` origen → destino |
| `01_load_staging.py` | Carga CSV a `dome_issuer.issuance_staging` |
| `02_etl_migrate.py` | ETL: transforma y mueve staging → issuance + auditoría |
| `03_reconcile.py` | Reconciliación: conteos, hashes, informe Markdown |
| `04_rollback.py` | Rollback controlado de la migración (opcional) |
| `05_backfill_created_at.py` | Post-migración: rellena `created_at` vacío a partir de la fecha del JSON de la credencial |
| `05_backfill_created_at_rollback.py` | Rollback del backfill: devuelve a `NULL` el `created_at` de las filas que rellenó (opcional) |
| `requirements.txt` | Dependencias Python (`psycopg2-binary`, `python-dotenv`) |
| `.env` | Credenciales y rutas (no commitear) |
| `.env.example` | Plantilla de `.env` |

---

## 3. Prerrequisitos

- [ ] Python 3.11 o superior instalado
- [ ] Cliente `psql` disponible (para extraer el CSV de IONOS)
- [ ] Acceso de red desde esta máquina a la BD destino (AWS RDS o Docker local)
- [ ] Schema `dome_issuer` ya existente en la BD destino (Flyway debe haber corrido)
- [ ] CSV extraído de IONOS y disponible localmente (ver paso 4.1)
- [ ] Archivo `.env` configurado con las credenciales correctas (ver paso 4.2)
- [ ] **PRD únicamente:** snapshot manual de RDS tomado antes de empezar (ver sección 10)

Instalar dependencias (una sola vez, en un entorno virtual):

```bash
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

pip install -r requirements.txt
```

---

## 4. Paso a paso

### 4.1 Extraer CSV de IONOS

Conectar a la BD de IONOS (base `identity`) y exportar la tabla completa. El orden de columnas debe ser exactamente este:

```sql
-- Ejecutar dentro de psql conectado a la base 'identity' en IONOS
\COPY (
  SELECT
    procedure_id,
    credential_id,
    credential_format,
    credential_decoded,
    credential_encoded,
    credential_status,
    organization_identifier,
    subject,
    valid_until,
    credential_type,
    operation_mode,
    signature_mode,
    email,
    created_at,
    created_by,
    updated_at,
    updated_by,
    notification_id
  FROM issuer.credential_procedure
  ORDER BY procedure_id
) TO '/tmp/credential_procedure_YYYYMMDD.csv' WITH CSV HEADER;
```

O desde la shell (sustituyendo las credenciales reales):

```bash
psql -h <IONOS_HOST> -U <IONOS_USER> -d identity \
  -c "\COPY (SELECT procedure_id, credential_id, credential_format, credential_decoded, credential_encoded, credential_status, organization_identifier, subject, valid_until, credential_type, operation_mode, signature_mode, email, created_at, created_by, updated_at, updated_by, notification_id FROM issuer.credential_procedure ORDER BY procedure_id) TO '/tmp/credential_procedure.csv' WITH CSV HEADER;"
```

Transferir el CSV resultante a la máquina donde se ejecutarán estos scripts.

> **Seguridad:** El CSV contiene PII (`email`, `subject`) y material criptográfico (`credential_decoded`, `credential_encoded`). Tratar según la política de clasificación de datos y eliminar una vez confirmada la migración.

---

### 4.2 Configurar el entorno

Copiar `.env.example` a `.env` y rellenar con los valores reales:

```bash
cp .env.example .env
```

Editar `.env`:

```dotenv
DB_HOST=<host-destino>
DB_PORT=5432
DB_NAME=<nombre-base-de-datos>
DB_USER=<usuario>
DB_PASSWORD=<contraseña>
DB_SSLMODE=disable          # Docker local: disable | AWS RDS (STG/PRD): require

CSV_INPUT_PATH=/ruta/al/credential_procedure.csv
REPORT_OUTPUT_DIR=./reports/
```

> **Nunca commitear `.env` al repositorio.**

---

### 4.3 Paso 1 — Cargar staging

```bash
python 01_load_staging.py
```

**Salida esperada (primera ejecución):**

```
─── 01_load_staging  summary ────────────────────
  Total rows in CSV  : 1224
  Rows inserted      : 1224
  Rows skipped       : 0  (already existed — ON CONFLICT DO NOTHING)
─────────────────────────────────────────────────
```

**Re-ejecución (idempotente):**

```
  Rows inserted      : 0
  Rows skipped       : 1224  (already existed — ON CONFLICT DO NOTHING)
```

---

### 4.4 Paso 2 — ETL: transformar y migrar

Ejecutar primero en dry-run para validar las transformaciones sin escribir nada en BD:

```bash
python 02_etl_migrate.py --dry-run
```

Si el dry-run es correcto, ejecutar la migración real:

```bash
python 02_etl_migrate.py
```

**Salida esperada:**

```
─── 02_etl_migrate  summary ─────────────────────
  Total rows processed : 1224
  OK                   : 1224
  HASH_MISMATCH        : 0
  SKIPPED              : 0
  Chunk errors         : 0
─────────────────────────────────────────────────
```

Re-ejecutar es seguro — `ON CONFLICT DO NOTHING` se aplica tanto en `issuance` como en `migration_audit`.

---

### 4.5 Paso 3 — Reconciliación

```bash
python 03_reconcile.py
```

El script escribe un informe Markdown y su checksum SHA-256 en `./reports/`.

**Salida esperada al final de la ejecución:**

```
─── 03_reconcile  summary ───────────────────────
  Staging rows      : 1224
  Issuance rows     : 1224
  Difference        : 0
  HASH_MISMATCH     : 0
  SKIPPED           : 0
  Tampered hashes   : 0
  Aggregate hash    : d46054e1...
  Report            : ./reports/migration_report_20260629_113947.md
─────────────────────────────────────────────────

RECONCILIATION PASSED — migration looks good.
```

Código de salida `0` = éxito. Código `1` = discrepancia (ver sección 9).

---

### 4.6 Paso 4 — Backfill de `created_at`

Ejecutar **después** de que el paso 3 termine en `RECONCILIATION PASSED`.

**Por qué es necesario:** una parte del histórico llega a `dome_issuer.issuance` con `created_at = NULL`, y el ETL lo copia tal cual:

- Credenciales emitidas antes de la migración `V7` del issuer v2 (2025-11-05), que añadió la columna `created_at` sin rellenar las filas existentes.
- Credenciales emitidas por el issuer v2 desde la versión 2.2.11 (2026-01-29): por un bug de auditoría (id preasignado sin `@Version`), Spring Data nunca rellenaba `created_at` ni `created_by`.

El script toma la fecha del JSON de la credencial (`credential_data_set`), por este orden de prioridad: `validFrom`, `vc.validFrom`, `issuanceDate`, `vc.issuanceDate`. No inventa valores: las filas sin fecha válida se dejan sin tocar y se informan para revisión manual. Lo mismo ocurre si la fecha encontrada es posterior al `updated_at` de la fila, porque es imposible como fecha de creación. `created_by` no es recuperable y sigue a `NULL`.

Ejecutar primero en dry-run y revisar el CSV generado en `./reports/`:

```bash
python 05_backfill_created_at.py --dry-run
```

Si el dry-run es correcto, ejecutar el backfill real:

```bash
python 05_backfill_created_at.py
```

**Salida esperada** (los recuentos dependen del entorno):

```
─── 05_backfill_created_at  summary ──────────
  Schema                     : dome_issuer
  Rows with created_at NULL  : <n>
    OK (validFrom)                      : <n1>
    OK (vc.validFrom)                   : <n2>
  Rows updated               : <n>
  Rows skipped (review)      : 0
  Rows with warnings (review): <w>  (updated anyway; see 'warnings' in the report)
    MIDNIGHT_UTC                        : <w1>
    SHARED_TIMESTAMP                    : <w2>

    credential_type                 rows  created_at (UTC)                   warnings
    LABEL_CREDENTIAL                  89  2024-08-22T00:00:00+00:00          MIDNIGHT_UTC, SHARED_TIMESTAMP
    ...

  Report                     : ./reports/backfill_created_at_dome_issuer_YYYYMMDD_HHMMSS.csv
─────────────────────────────────────────────────────
```

Código de salida `0` = todas las filas rellenadas. Código `1` = hay filas sin rellenar (ver sección 9).

**Avisos (`warnings`):** en LabelCredential y VerifiableCertification (y en las primeras LEARCredentialMachine) el `validFrom` venía en la petición de emisión, así que puede no ser el momento de emisión. Esas filas **se rellenan igualmente**, pero el informe las marca en la columna `warnings` para revisión. Los avisos no cambian lo que se escribe ni el código de salida.

| Aviso | Significado |
|---|---|
| `MIDNIGHT_UTC` | Fecha exactamente a las 00:00:00.000 UTC — típico de una fecha puesta a mano |
| `SHARED_TIMESTAMP` | La misma fecha exacta en 3 o más filas — copiada de la petición, no generada al emitir |
| `FUTURE` | Fecha posterior al momento de ejecución |

Referencia SBX (2026-10-14): 107 filas con aviso de 1.156 — 89 LabelCredential y 6 VerifiableCertification a `2024-08-22T00:00:00Z`, 7 LabelCredential a `2025-09-24T09:56:59.296Z` y 5 LEARCredentialMachine a `2024-01-01T08:00:00Z`. Se decidió dejarlas con la fecha del JSON.

- **Idempotente:** solo lee filas con `created_at IS NULL` y el `UPDATE` vuelve a comprobarlo, así que nunca sobrescribe un valor existente.
- **Sin PII en logs ni en el informe:** solo se registran `issuance_id`, resultado, fuente y fecha asignada.
- `--schema <schema>` permite ejecutarlo sobre otro schema de tenant (por defecto `dome_issuer`).
- **Ejecutarlo con el issuer sin tráfico** (por ejemplo, dentro de la ventana de cutover): el script no incrementa `version`, así que una escritura concurrente del issuer sobre la misma fila podría volver a dejar `created_at` a `NULL`.
- **Guardar el CSV de la ejecución real** (el que no lleva `_dry-run`) fuera de la máquina si hace falta: es la única entrada del rollback de este paso (sección 10). `reports/` está en `.gitignore`, así que solo existe en el equipo que ejecutó el backfill.

---

## 5. Validación post-migración

Ejecutar estas consultas en la BD destino para verificar el estado:

```sql
-- Conteo total migrado
SELECT COUNT(*) FROM dome_issuer.issuance
WHERE issuance_id IN (SELECT source_record_id FROM dome_issuer.migration_audit);

-- Distribución de estados en destino
SELECT credential_status, COUNT(*) AS n
FROM dome_issuer.issuance
WHERE issuance_id IN (SELECT source_record_id FROM dome_issuer.migration_audit)
GROUP BY credential_status
ORDER BY n DESC;

-- Verificar que no quedan HASH_MISMATCH en la auditoría
SELECT outcome, COUNT(*) AS n
FROM dome_issuer.migration_audit
GROUP BY outcome;

-- Verificar integridad del audit (sin registros manipulados)
SELECT COUNT(*) AS tampered
FROM dome_issuer.migration_audit
WHERE outcome = 'OK'
  AND source_hash IS DISTINCT FROM target_hash;

-- Tras el paso 4: no deben quedar filas sin created_at (0 esperado)
SELECT credential_type, COUNT(*) AS n
FROM dome_issuer.issuance
WHERE created_at IS NULL
GROUP BY credential_type;
```

**Resultados esperados en PRD:**

| Estado destino | Recuento estimado |
|---|--:|
| `EXPIRED` | 522 |
| `VALID` | 289 |
| `WITHDRAWN` | ~378 (DRAFT + PEND_SIGNATURE + WITHDRAWN origen) |
| `REVOKED` | 33 |
| `ARCHIVED` | ~2 (ISSUED origen — datos de prueba) |
| `ISSUED` | 0 (PEND_DOWNLOAD sin registros en PRD) |

**Verificar integridad del informe de reconciliación:**

```powershell
# Windows (PowerShell)
$expected = (Get-Content migration_report_YYYYMMDD_HHMMSS.md.sha256).Split(' ')[0]
$actual   = (Get-FileHash migration_report_YYYYMMDD_HHMMSS.md -Algorithm SHA256).Hash.ToLower()
$expected -eq $actual
```

```bash
# Linux / macOS
sha256sum -c migration_report_YYYYMMDD_HHMMSS.md.sha256
```

El aggregate hash de PRD será diferente al de SBX. Guardarlo del informe como evidencia post-cutover.

---

## 6. Interpretar el informe de reconciliación

El informe Markdown en `./reports/` contiene las siguientes secciones:

| Sección | Qué indica |
|---|---|
| **Row counts** | Filas en staging vs. issuance; `Difference` debe ser `0 ✅` |
| **Integrity checks** | HASH_MISMATCH, SKIPPED y Tampered hashes; todos deben ser `0 ✅` |
| **Aggregate verification hash** | SHA-256 de todos los `target_hash` OK — guardar como evidencia post-cutover |
| **Status transformations** | Conteo por mapeo de estado; validar contra la distribución conocida |
| **HASH_MISMATCH records** | `issuance_id` con discrepancia de hash (vacío si todo es correcto) |
| **RECONCILIATION PASSED / FAILED** | Veredicto final — ✅ o ❌ |

---

## 7. Mapeo de estados

Decisiones acordadas con PO. No modificar sin nueva validación.

| Estado origen (`credential_status`) | Estado destino | Motivo |
|---|---|---|
| `EXPIRED` | `EXPIRED` | Copia directa |
| `DRAFT` | `WITHDRAWN` | Oferta nunca canjeada — en v3 los DRAFT >1 mes pasan automáticamente a WITHDRAWN |
| `VALID` | `VALID` | Copia directa |
| `REVOKED` | `REVOKED` | Copia directa |
| `PEND_SIGNATURE` | `WITHDRAWN` | Nunca firmados, 6–11 meses de antigüedad — misma semántica "nunca canjeado" que DRAFT |
| `ISSUED` | `ARCHIVED` | Los registros de PRD son datos de prueba dejados en estado de error |
| `PEND_DOWNLOAD` | `ISSUED` | 0 registros en PRD; equivalente semántico más cercano |
| `WITHDRAWN` | `WITHDRAWN` | Equivalente directo — consistente con DRAFT y PEND_SIGNATURE |

Cualquier valor no listado provoca `UnmappedStatusError` y aborta el chunk actual. Añadir el nuevo valor a `STATUS_MAP` en `status_mapping.py` tras confirmar con PO el estado destino correcto.

---

## 8. Campos descartados del origen

Los siguientes campos de `issuer.credential_procedure` no tienen equivalente en `dome_issuer.issuance` y se descartan durante la migración. Es una decisión acordada, no una omisión accidental.

| Campo origen | Motivo del descarte |
|---|---|
| `operation_mode` | Concepto eliminado en EUDIStack v3 |
| `signature_mode` | Concepto eliminado en EUDIStack v3 |
| `notification_id` | ID interno de notificación legacy, sin equivalente en v3 |

Estos campos siguen disponibles en `dome_issuer.issuance_staging`, que persiste después del ETL y puede consultarse para trazabilidad.

---

## 9. Errores frecuentes y soluciones

### ERROR: `EnvironmentError: Required environment variable 'DB_HOST' is not set`

**Causa:** El archivo `.env` no existe o la variable está vacía.
**Solución:** Copiar `.env.example` a `.env` y rellenar todos los campos obligatorios.

---

### ERROR: `psycopg2.OperationalError: could not connect to server`

**Causa:** Host, puerto, credenciales incorrectas, o red inaccesible.
**Solución:**
1. Verificar conectividad: `psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME`
2. Si el destino es AWS RDS, asegurar que `DB_SSLMODE=require` en `.env`.
3. Si es Docker local, verificar que el contenedor esté levantado.

---

### ERROR: `SSL connection required` / `SSL off`

**Causa:** `DB_SSLMODE` no coincide con el requerimiento del servidor.
**Solución:** Usar `DB_SSLMODE=require` para AWS RDS, `DB_SSLMODE=disable` para Docker local.

---

### ERROR: `Schema dome_issuer does not exist` (exit code 2)

**Causa:** Las migraciones Flyway no se han ejecutado en el entorno destino.
**Solución:** Ejecutar el pipeline de Flyway en el entorno correspondiente antes de lanzar el ETL.

---

### ERROR: `UnmappedStatusError: No mapping defined for credential_status='XXXX'`

**Causa:** La BD origen contiene un valor de `credential_status` no contemplado en `STATUS_MAP`.
**Solución:**
1. Identificar el valor en cuestión del mensaje de error.
2. Consultar con PO qué estado destino corresponde.
3. Añadir la entrada a `STATUS_MAP` en `status_mapping.py`.
4. Re-ejecutar el script 02 (idempotente — no duplicará los ya migrados).

---

### ERROR: `RECONCILIATION FAILED` — diferencia de filas ≠ 0

**Causa:** Algún chunk del script 02 abortó por error y no todas las filas se migraron.
**Solución:**
1. Revisar los logs del script 02 para identificar el chunk fallido.
2. Corregir el problema de fondo (generalmente un `UnmappedStatusError`).
3. Re-ejecutar `python 02_etl_migrate.py` — las filas ya migradas se saltarán.
4. Re-ejecutar `python 03_reconcile.py` para regenerar el informe.

---

### ERROR: `RECONCILIATION FAILED` — Tampered hashes > 0

**Causa:** Se han modificado directamente los valores de `target_hash` en `dome_issuer.migration_audit` después de la migración.
**Solución:** Investigar quién modificó la tabla de auditoría. Si la integridad está comprometida, hacer rollback y re-ejecutar la migración completa.

---

### WARNING: `05_backfill_created_at` termina con `Rows skipped (review)` > 0

**Causa:** Alguna fila no tiene una fecha utilizable en `credential_data_set`, o la que tiene no es coherente con la propia fila. El resultado indica el motivo:

| Resultado | Significado |
|---|---|
| `SKIPPED_INVALID_JSON` | `credential_data_set` vacío o no es un objeto JSON válido |
| `SKIPPED_NO_DATE` | El JSON no contiene `validFrom` ni `issuanceDate` (ni en raíz ni bajo `vc`) |
| `SKIPPED_UNPARSEABLE_DATE` | Hay fecha, pero no es ISO-8601 válida |
| `SKIPPED_AFTER_UPDATED_AT` | Hay fecha válida, pero es posterior al `updated_at` de la fila — imposible como fecha de creación. La fecha descartada aparece en la columna `created_at` del CSV para poder revisarla |

**Solución:**
1. Localizar las filas afectadas en el CSV de `./reports/` (columna `outcome`).
2. Decidir con PO el valor a asignar (por ejemplo, `updated_at`) y aplicarlo manualmente por `issuance_id`.
3. Re-ejecutar el script es seguro: solo procesa las filas que siguen con `created_at IS NULL`.

---

## 10. Rollback

### Prerrequisito obligatorio en PRD — snapshot de RDS

> **⚠️ TOMAR SNAPSHOT ANTES DE EJECUTAR EL ETL EN PRD**
>
> Crear un snapshot manual de la instancia RDS justo antes de ejecutar el script 01 en producción. Es el fallback de último recurso si el rollback SQL falla. Retención mínima: 90 días.
>
> ```bash
> aws rds create-db-snapshot \
>   --db-instance-identifier <eudistack-prd-instance> \
>   --db-snapshot-identifier dome-migration-pre-etl-YYYYMMDD
> ```
>
> El rollback SQL descrito abajo solo funciona si `dome_issuer.issuance` no ha recibido escrituras de producto entre el ETL y el rollback. Si hubo escrituras, restaurar desde el snapshot es la única opción segura.

---

### Rollback con `04_rollback.py` (recomendado)

Lee los IDs exactos de `migration_audit` y elimina únicamente las filas que insertó este ETL, dentro de una única transacción.

```bash
# Ver qué se borraría sin ejecutar nada
python 04_rollback.py --dry-run

# Rollback con confirmación interactiva (escribe 'ROLLBACK' para confirmar)
python 04_rollback.py

# Rollback sin confirmación + vaciar también issuance_staging
python 04_rollback.py --yes --staging
```

**Salida esperada (dry-run):**

```
─── 04_rollback  plan ───────────────────────────────
  Filas en migration_audit          : 1224
  Filas en issuance (a eliminar)    : 1224
  Limpiar issuance_staging          : no
─────────────────────────────────────────────────────
[DRY-RUN] No se ha borrado nada.
```

**Salida esperada (rollback ejecutado):**

```
─── 04_rollback  resultado ──────────────────────────
  Filas eliminadas de issuance      : 1224
  Filas restantes en issuance       : 0
  Filas restantes en migration_audit: 0
─────────────────────────────────────────────────────
Rollback completado. Puedes volver a ejecutar 01 → 02 → 03.
```

| Flag | Cuándo usarlo |
|---|---|
| `--dry-run` | Verificar el plan antes de ejecutar |
| `--yes` | Sin confirmación interactiva (automatización, CI) |
| `--staging` | Vacía también `issuance_staging` además de `issuance` y `migration_audit` |

---

### Rollback manual (alternativa SQL)

**Solo staging cargado (script 01 ejecutado, script 02 no):**

```sql
TRUNCATE TABLE dome_issuer.issuance_staging;
```

**Staging + ETL completados (scripts 01 y 02 ejecutados):**

```sql
-- Eliminar filas migradas
DELETE FROM dome_issuer.issuance
WHERE issuance_id IN (SELECT source_record_id FROM dome_issuer.migration_audit);

-- Limpiar el registro de auditoría
TRUNCATE TABLE dome_issuer.migration_audit;

-- Opcional: limpiar staging también
TRUNCATE TABLE dome_issuer.issuance_staging;
```

> El rollback elimina únicamente las filas que insertó esta migración. No afecta a ninguna fila creada por flujos normales de producto — los `issuance_id` de `procedure_id` son UUIDs únicos del sistema origen y no colisionan.

Tras el rollback, corregir el problema, re-extraer el CSV si es necesario, y volver a empezar desde el paso 4.3.

---

### Rollback del paso 4 (backfill de `created_at`)

`04_rollback.py` **no** cubre el paso 4: borra las filas migradas en lugar de deshacer el backfill. Para devolver a `NULL` solo el `created_at` que rellenó `05_backfill_created_at.py`, usar `05_backfill_created_at_rollback.py` con el CSV de la **ejecución real** del paso 4:

```bash
# Ver qué se revertiría sin ejecutar nada
python 05_backfill_created_at_rollback.py --report reports/backfill_created_at_dome_issuer_YYYYMMDD_HHMMSS.csv --dry-run

# Rollback con confirmación interactiva (escribe 'ROLLBACK' para confirmar)
python 05_backfill_created_at_rollback.py --report reports/backfill_created_at_dome_issuer_YYYYMMDD_HHMMSS.csv
```

| Flag | Uso |
|---|---|
| `--report <csv>` | Obligatorio. Informe de la ejecución real del paso 4. Se rechaza un informe `_dry-run` (lista lo que se habría escrito, no lo que se escribió) y uno generado para otro schema |
| `--dry-run` | Verificar el plan antes de ejecutar |
| `--yes` | Sin confirmación interactiva |
| `--schema <schema>` | Schema del tenant (por defecto `dome_issuer`); debe coincidir con el del informe |

Solo revierte las filas con `outcome = OK` del informe **cuyo `created_at` sigue siendo exactamente el valor escrito por el backfill**. El plan clasifica el resto sin tocarlo:

| Estado | Significado | Acción |
|---|---|---|
| to revert | `created_at` conserva el valor del backfill | Se devuelve a `NULL` |
| already NULL | Ya está a `NULL` (p. ej. rollback repetido) | Nada |
| changed since | Tiene otro valor: alguien lo cambió tras el backfill | Se deja; revisar a mano |
| not found | El `issuance_id` ya no existe | Se deja; revisar a mano |

Todo ocurre en una única transacción: si el número de filas revertidas no coincide con el plan (cambio concurrente), no se escribe nada y basta con volver a ejecutarlo. Código de salida `0` = todo revertido; `1` = quedan filas para revisión, o se canceló.

**Sin el CSV:** si el informe se ha perdido, la alternativa es la copia de los `issuance_id` que tenían `created_at IS NULL`, tomada antes del backfill:

```sql
UPDATE dome_issuer.issuance
   SET created_at = NULL
 WHERE issuance_id IN (SELECT issuance_id FROM dome_issuer.bkp_created_at_null_YYYYMMDD);
```

---

## 11. Orden de ejecución resumido

```
[ ] 1. psql → exportar CSV desde IONOS
[ ] 2. Copiar CSV a esta máquina
[ ] 3. Configurar .env (credenciales destino, DB_SSLMODE, ruta CSV)
[ ] 4. python -m venv .venv && pip install -r requirements.txt
[ ] 5. python 01_load_staging.py           <- carga staging
[ ] 6. python 02_etl_migrate.py --dry-run  <- validar transformaciones
[ ] 7. python 02_etl_migrate.py            <- ETL real
[ ] 8. python 03_reconcile.py              <- reconciliación + informe
[ ] 9. Revisar informe en ./reports/       <- debe terminar en RECONCILIATION PASSED
[ ] 10. python 05_backfill_created_at.py --dry-run  <- revisar CSV en ./reports/
[ ] 11. python 05_backfill_created_at.py            <- backfill real; Rows skipped debe ser 0
[ ] 12. Guardar el CSV de la ejecución real         <- entrada del rollback del paso 4
[PRD] Guardar aggregate hash del informe como evidencia post-cutover
[PRD] Eliminar CSV local tras confirmar migración exitosa
```

En caso de error en cualquier paso: ver sección 9 (errores frecuentes) o ejecutar `python 04_rollback.py --dry-run` para evaluar el estado antes de decidir si revertir. Si el problema está en el paso 4, el rollback es `05_backfill_created_at_rollback.py --dry-run` (sección 10).
