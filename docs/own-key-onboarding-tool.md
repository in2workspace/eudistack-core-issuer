# Own-key onboarding tool (EUD-289)

Puts a tenant's own signing key, held in AWS KMS, into service (modality `own_key`), replaces it, and retires
the KMS key of a replaced configuration. It is **not** the Issuer service: it is a separate process that an
operator or a scheduler launches and that ends, with its own exit code. It lives in the Issuer jar only to reuse
the Issuer's certificate checks.

It runs with the **operation role**: `kms:CreateKey`, `kms:TagResource`, `kms:CreateAlias`,
`kms:GetParametersForImport`, `kms:ImportKeyMaterial`, `kms:GetPublicKey`, `kms:DisableKey`,
`kms:ScheduleKeyDeletion`, `kms:DescribeKey` (reconcile, discard), `kms:ListResourceTags` (discard) and
`kms:DeleteAlias` (discard). `sts:GetCallerIdentity` needs no permission. It has no `kms:Sign`: the key is checked by comparing its public key with the
certificate. It never receives a private key in clear.

## Commands

| Command | What it does |
|---------|--------------|
| `prepare` | Validates the certificate chain and the tenant. Creates the KMS key (external origin, ECC_NIST_P256, SIGN_VERIFY, tags `Tenant=<tenant>` and `operationId=<uuid>`) with an alias, asks KMS for the import parameters (`RSA_AES_KEY_WRAP_SHA_256`, RSA_4096) and writes to `--out-dir`: `own-key-<tenant>-<operationId>.{wrapping-public-key.der,wrapping-public-key.pem,import-token.bin,state.json}`. Nothing in them is secret. If anything fails after `CreateKey`, the new key is disabled and its deletion scheduled. |
| `import` | Reads the state file and the key material the customer wrapped with the wrapping public key. Validates again (the state may be stale), imports with `KEY_MATERIAL_DOES_NOT_EXPIRE`, requires `GetPublicKey` to be byte-identical to the certificate's SPKI and, in **one database transaction**, locks the tenant's active row, withdraws it (a QTSP row loses `credentialPwd`, `clientSecret`, `accessKey`, `credentialId`; an own-key row loses its SPKI reservation), inserts the new active `own_key` row, reserves the SPKI in `public.signing_spki_reservation` and stages the audit event. If anything fails after the import, the key is disabled and its deletion scheduled and the database is unchanged. |
| `discard` | Gives up a preparation that was never imported (`--state`): checks that the KMS key is the one of that preparation (tags `operationId` and `Tenant` equal the state's), that it is still waiting for its key material (PendingImport) and that no `tenant_signing_config` row of any tenant references its ARN; then disables it if possible, schedules its deletion, deletes its alias and marks the state file (`discardedAt`), which `import` then refuses. It refuses with exit 2 a key that has material imported, other tags or a reference. A key already pending deletion or gone only gets the state marked, so it can be repeated. A renewal has nothing to discard. |
| `reconcile` | For every active tenant, takes (`FOR UPDATE SKIP LOCKED`, one transaction per row) the `own_key` rows withdrawn for longer than the grace period (default 160 s) whose key is not marked yet, checks the key state, disables it if enabled, schedules its deletion (default 7 days, the KMS minimum) and sets `own_key_deleted_at`. Idempotent: a second run makes no KMS call. |

**Renewal keeping the key.** If the certificate's SPKI is reserved by the same tenant and by that tenant's
currently active own-key row, it is a renewal of that row's certificate: the key material is already in its KMS
key, so nothing is created or imported. `prepare` checks that `GetPublicKey` of the existing key equals the new
certificate's SPKI and leaves only a state file marked `renewal`; `import --state` (no key material, no token) checks
it again and, in one transaction, withdraws the old row, inserts the new active row with the **same key ARN**, moves
the reservation to the new row and stages a `Replace` event. The old row is marked handled
(`own_key_deleted_at`) and `reconcile` never disables or schedules the deletion of a key that an active row of any
tenant references. A failed renewal never touches the existing key. Any other holder of the SPKI (another tenant, or
a stale reservation of the same tenant not tied to the active row) is still rejected as `KeyInUse`.

There is **no withdrawal command**: a configuration is only withdrawn by its replacement (`import`), and the
active configuration of a tenant is never withdrawn without one. Run `reconcile` every 15 to 20 minutes, or by hand.

Every command accepts `--dry-run`: validations only, nothing is written to KMS, files or the database
(`reconcile --dry-run` reads the key states and reports what it would do).

## Validations (`prepare` and `import`, before anything is created or imported)

The chain parses; the key is P-256; the leaf is an end-entity certificate whose `keyUsage`, if present, allows
`digitalSignature` or `nonRepudiation`; every certificate links to the next, which is a CA; the leaf and the
intermediates are valid now (always); the certificate does not declare a QSCD (QCP-n-qscd, QCP-l-qscd, QcSSCD);
the tenant is active in `public.tenant_registry` and its `<tenant>_issuer` schema exists; the SPKI SHA-256 is not
reserved by any tenant, except for a renewal of the tenant's own active key (above). With `--production` the certificate is also not self-signed, the
chain ends in the agreed CA (`--trust-anchor`) and the leaf carries the tenant's `organizationIdentifier`
(`--expected-org-id`); both are mandatory with `--production` and are checked whenever they are given.

## Launching it

From the Issuer's Spring Boot jar (Java 25), with the `PropertiesLauncher`:

```bash
java -cp issuer.jar \
     -Dloader.main=es.in2.issuer.backend.signing.infrastructure.onboarding.OwnKeyOnboardingMain \
     org.springframework.boot.loader.launch.PropertiesLauncher \
     <command> [options]
```

From the Issuer image, overriding its entrypoint (the image's `ENTRYPOINT` is `java -jar /app/issuer.jar`, which
starts the service). If the task sets `JAVA_TOOL_OPTIONS` with the ADOT agent, unset it for this process:

```bash
docker run --rm --entrypoint java <issuer-image> \
     -cp /app/issuer.jar \
     -Dloader.main=es.in2.issuer.backend.signing.infrastructure.onboarding.OwnKeyOnboardingMain \
     org.springframework.boot.loader.launch.PropertiesLauncher <command> [options]
```

On ECS this is a one-off task (or a scheduled task for `reconcile`) with that `entryPoint` and `command`, and
the same environment as the Issuer task. `--help` prints the usage.

## Configuration

Arguments or environment variables; an argument wins. The names of the database and KMS variables are the Issuer's.

| Setting | Argument | Environment variable |
|---------|----------|----------------------|
| JDBC URL | `--db-url` | `SPRING_FLYWAY_URL` |
| Database user | `--db-user` | `SPRING_R2DBC_USERNAME` |
| Database password | (never an argument) | `SPRING_R2DBC_PASSWORD` |
| AWS region | `--kms-region` | `ISSUER_SIGNING_KMS_REGION`, then `AWS_REGION` |
| Endpoint override (LocalStack; KMS and STS) | `--kms-endpoint` | `ISSUER_SIGNING_KMS_ENDPOINT` |
| AWS credentials | | SDK default chain (task role, SSO, `AWS_*`) |
| Pending window of `ScheduleKeyDeletion`, 7 to 30 | `--deletion-window-days` | `OWN_KEY_DELETION_WINDOW_DAYS` |
| Validations only | `--dry-run` | `OWN_KEY_DRY_RUN` |
| `prepare`: tenant, chain (PEM, leaf first, root excluded), output directory, alias | `--tenant`, `--cert-chain`, `--out-dir`, `--alias` | `OWN_KEY_TENANT`, `OWN_KEY_CERT_CHAIN`, `OWN_KEY_OUT_DIR`, `OWN_KEY_ALIAS` |
| `import`: state, wrapped key material, import token (default: next to the state) | `--state`, `--key-material`, `--import-token` | `OWN_KEY_STATE`, `OWN_KEY_KEY_MATERIAL`, `OWN_KEY_IMPORT_TOKEN` |
| `prepare` and `import`: production checks | `--production`, `--trust-anchor`, `--expected-org-id` | `OWN_KEY_PRODUCTION`, `OWN_KEY_TRUST_ANCHOR`, `OWN_KEY_EXPECTED_ORG_ID` |
| `discard`: state file of the preparation | `--state` | `OWN_KEY_STATE` |
| `reconcile`: grace period in seconds (default 160) | `--grace-seconds` | `OWN_KEY_GRACE_SECONDS` |

The default alias is `alias/own-key-<tenant>-<operationId>`. The key policy is the KMS default until Infra defines
a fixed one; it is injected through the constructor of `AwsKmsKeyAdministrationAdapter`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Done (or `--help`). |
| 1 | Any other error (KMS, database, files). `reconcile` ends with 1 if any key could not be reconciled; the rest were. |
| 2 | Onboarding rejected by a validation: the reason is on stderr, nothing was put into service. |
| 64 | Usage error. |

Results go to stdout; logs and errors to stderr.

## Audit

Each created or replaced configuration, and each rejected onboarding, produces a `SigningConfigurationChanged`
event (EUD-244 catalogue: `operation` Create or Replace, previous and new modality, certificate fingerprint, result
and, if rejected, reason `PolicyDenied`, `InvalidKey`, `InvalidCertificate` or `KeyInUse`; actor = the caller ARN;
duration). A rejection because the tenant is not in `public.tenant_registry` or is not active is audited like any other, with the tenant id as given (the audit API keeps the events of an unknown tenant as rejected events of its own), and also leaves a warn log line. The event is staged in the same transaction as the change; a rejection is recorded in a transaction of its
own. Until the outbox of EUD-244 exists, `LoggingSigningConfigurationAuditSink` writes it as a JSON line to the
logger `es.in2.issuer.backend.signing.onboarding.audit` after the commit. The event holds no secrets and no key
ARN. To use the outbox, implement `SigningConfigurationAuditSink.stage` (an insert on the given connection, or the
EUD-244 starter); nothing else changes.

`activated_by` and `withdrawn_by` hold the caller ARN from STS `GetCallerIdentity`, never free text.
