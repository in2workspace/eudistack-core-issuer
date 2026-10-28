# Own-key onboarding tool (EUD-289)

Puts a tenant's own signing key, held in AWS KMS, into service (modality `own_key`), replaces it, and retires
the KMS key of a replaced configuration. It is **not** the Issuer service: it is a separate process that an
operator or a scheduler launches and that ends, with its own exit code. It lives in the Issuer jar only to reuse
the Issuer's certificate checks.

It runs with the **operation role**: `kms:CreateKey`, `kms:TagResource`, `kms:CreateAlias`,
`kms:GetParametersForImport`, `kms:ImportKeyMaterial`, `kms:GetPublicKey`, `kms:DisableKey`,
`kms:ScheduleKeyDeletion`, `kms:DescribeKey` (`import`, `discard`, `reconcile`, and in the compensation of `prepare`; also on the alias, to check it points to the key), `kms:ListResourceTags` (`import`, `discard`) and
`kms:DeleteAlias` (`import`, `discard` and the compensation of `prepare`). `sts:GetCallerIdentity` needs no permission (it also gives the account that `--expected-aws-account` is compared with). It has no `kms:Sign`: the key is checked by comparing its public key with the
certificate. It never receives a private key in clear.

## Commands

| Command | What it does |
|---------|--------------|
| `prepare` | Validates the certificate chain and the tenant. Creates the KMS key (external origin, ECC_NIST_P256, SIGN_VERIFY, tags `Tenant=<tenant>` and `operationId=<uuid>`) with an alias, asks KMS for the import parameters (`RSA_AES_KEY_WRAP_SHA_256`, RSA_4096) and writes to `--out-dir`: `own-key-<tenant>-<operationId>.{wrapping-public-key.der,wrapping-public-key.pem,import-token.bin,state.json}`. Nothing in them is secret. If anything fails after `CreateKey`, the new key is disabled and its deletion scheduled. |
| `import` | Reads the state file and the key material the customer wrapped with the wrapping public key. Validates again (the state may be stale), imports with `KEY_MATERIAL_DOES_NOT_EXPIRE`, requires `GetPublicKey` to be byte-identical to the certificate's SPKI and, in **one database transaction**, locks the tenant's active row, withdraws it (a QTSP row loses `credentialPwd`, `clientSecret`, `accessKey`, `credentialId`; an own-key row keeps its SPKI reservation until `reconcile` retires its key), inserts the new active `own_key` row, reserves the SPKI in `public.signing_spki_reservation` and stages the audit event. If anything fails after the import, the key is disabled and its deletion scheduled and the database is unchanged, but only if this very run imported the key material: an enabled key that this run did not import is never touched. A whole run of `import` holds a PostgreSQL **session advisory lock** of its operation (taken before the first check, released when the run ends, also on failure), so two runs of the same state cannot overlap; once it holds the lock it reads the state file again and refuses it if another run marked it meanwhile; the second one ends with exit 1 and touches nothing in KMS (`--dry-run` takes no lock). After the commit it checks that the key is `ENABLED`; if it is not, the commit stands, the key is not touched and the run ends with exit 1 saying so. |
| `discard` | Gives up a preparation that was never imported (`--state`): checks that the KMS key is the one of that preparation (tags `operationId` and `Tenant` equal the state's), that it is still waiting for its key material (PendingImport) and that no `tenant_signing_config` row of any tenant references its ARN; then disables it if possible, schedules its deletion, deletes its alias and marks the state file (`discardedAt`), which `import` then refuses. It refuses with exit 2 a key that has material imported, other tags or a reference. A key already pending deletion or gone only gets the state marked, so it can be repeated. A refusal is audited as a denied `Retire` and a successful discard as a `Retire` success. A renewal has nothing to discard. A real `discard` takes the same session advisory lock as `import` (`--dry-run` takes none), so it never runs in the middle of an `import` of the same preparation. |
| `reconcile` | For every active tenant, takes (`FOR UPDATE SKIP LOCKED`, one transaction per row) the `own_key` rows withdrawn for longer than the grace period (default 160 s) whose key is not marked yet, checks the key state, disables it if enabled, schedules its deletion (default 7 days, the KMS minimum), sets `own_key_deleted_at` and, in the same transaction, **releases the SPKI reservation** of that row, and stages a `Retire` event. If an active configuration of any tenant still references the key, the key is left alone and the row is marked handled **without releasing its reservation** (`Retire` `Denied` `KeyInUse`): the key still signs, so its public key stays reserved. If that active configuration is of the same tenant, the reservation passes to it (so it is released when that configuration's key is retired, and a renewal of its certificate is recognised); if only another tenant's configuration uses the key, the reservation stays on the row and an error is logged, because nothing will release it: check by hand which tenant must hold the key. These are anomalous states (rows not written by this tool, or the same key referenced as a KeyId and as an ARN). Idempotent: a second run makes no KMS call. It asks STS for the caller identity (the actor of the events) only when it has a row to process, once per run, so in non-production a run with nothing to retire does not depend on STS (in production it does anyway: the check of `--expected-aws-account` calls STS when the tool starts). |

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
reserved by any tenant, except for a renewal of the tenant's own active key (above). When the reservation that blocks an onboarding belongs to the **same tenant** (the key was in a configuration that has been replaced), the rejection says so: the reservation is released when `reconcile` retires that key, after the grace period and in its next run. The production checks are the **default**: the certificate is also not self-signed, the
chain ends in the agreed CA (`--trust-anchor`) and the leaf carries the tenant's `organizationIdentifier`
(`--expected-org-id`); both are mandatory and are checked whenever they are given. `--non-production` is for local and STG environments only and exists **only as a command line argument** (see *Production mode* below): it accepts a self-signed certificate, a missing trust anchor and organization id, a missing key policy and account, `--kms-endpoint` (which is rejected without it) and the SDK endpoint variables. `prepare` stores a summary of its policy in the state file (production yes/no, SHA-256 of the trust anchor, organization id) and `import` rejects (`PolicyDenied`) a policy laxer than or different from it. A state without that summary (old, or edited by hand) counts as prepared with the production checks: `import` accepts it only with them.

## Production mode

Production checks are the default and cannot be switched off by the environment:

- `--non-production` is a **command line argument only**. The variable `OWN_KEY_NON_PRODUCTION` is no longer read, and if it is set in the environment the tool ends with a usage error (exit 64) that says so, so that a variable left in a task definition, an image or an `.env` copied from STG cannot weaken the checks without anyone noticing. `--non-production=false` is production.
- In production mode `--expected-aws-account <12 digits>` (or `OWN_KEY_EXPECTED_AWS_ACCOUNT`) is mandatory, for every command. The tool compares it with the account of the credentials, as STS `GetCallerIdentity` reports it, before it touches KMS or the database; another account ends with **exit 2** and nothing is touched. With `--non-production` it is not required, and it is checked if given.
- In production mode the run is refused (usage error, exit 64) if the AWS SDK is configured with an endpoint override: environment variables `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_<SERVICE>` or system properties `aws.endpointUrl*` (the error names them, never their values). The KMS and STS clients are also built with `aws.ignoreConfiguredEndpointUrls=true`, so an `endpoint_url` of the AWS profile is ignored too. Without this a redirected STS would make the actor of the audit event (the caller ARN) untrustworthy. In `--non-production` they are allowed, for emulators such as LocalStack.
- Every run says its mode: `checks: production` or `checks: NON-PRODUCTION (...)` on stdout and a log line, which is a `WARN` in non-production. The mode is **not** a field of the audit event: the EUD-244 catalogue (2.2.0) allows no other `details` than `operation`, `previous_modality`, `new_modality` and `signing_certificate`, and the audit API rejects any other field. It is in the log and the output of the run.

## Running in production

The production checks protect against mistakes, not against whoever controls how the tool is launched: `--non-production`
given by hand switches them off, and a run in that mode leaves the same audit event as a production one (the EUD-244
catalogue 2.2.0 has no field for the mode; it is only on stdout and in a `WARN` of the log). The tool does not know which
AWS accounts are production. So in PRO the guarantee is in **how it is launched**, and this is a requirement for infra:

- **Only a controlled path launches it in PRO**: a GitHub Action with input fields (the command and its parameters, never
  free arguments), or one ECS task definition per command. That path **never adds `--non-production`** and always passes
  `--expected-aws-account` with the PRO account.
- **Nobody launches it any other way in PRO**: nobody has `ecs:RunTask` with container overrides (command, environment,
  entry point), nor `ecs:RegisterTaskDefinition` for the tool's task, nor can assume the operation role directly. Only
  that path can.
- **The same path injects the key policy from SSM Parameter Store** into `OWN_KEY_KEY_POLICY_JSON` (the `secrets` of the
  task definition, or the step of the Action), so the operator cannot change it either (see *Key policy*).
- **The task definition is a trust asset.** Whoever controls it (its environment, `JAVA_TOOL_OPTIONS`, an HTTPS proxy or a
  trust store of the JVM) can redirect STS and falsify the actor and the account. Its changes go through the review of the
  infrastructure code like any other.

If infra cannot set it up this way, it must tell the team before the tool is used in PRO: the alternative, a list of the
production accounts in SSM that the tool reads to refuse `--non-production` in them, needs a change in the tool.

## Local environments

Keys onboarded before M1 (for example with the bash tool `local-onboard-cgcom.sh`) have no `Tenant` tag, and the Issuer
refuses to sign with a KMS key that is not tagged for the request tenant. Tag them, or onboard them again with this tool:

```bash
awslocal kms tag-resource --key-id <id> --tags TagKey=Tenant,TagValue=<tenant>
```

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
| Where the audit events go: `log` (default) or `outbox` | `--audit-sink` | `OWN_KEY_AUDIT_SINK` |
| `prepare`: tenant, chain (PEM, leaf first, root excluded), output directory, alias | `--tenant`, `--cert-chain`, `--out-dir`, `--alias` | `OWN_KEY_TENANT`, `OWN_KEY_CERT_CHAIN`, `OWN_KEY_OUT_DIR`, `OWN_KEY_ALIAS` |
| `prepare`: key policy, a file or the JSON itself (one of them, mandatory unless `--non-production`) | `--key-policy` (file) | `OWN_KEY_KEY_POLICY` (file), `OWN_KEY_KEY_POLICY_JSON` (the JSON) |
| `import`: state, wrapped key material, import token (default: next to the state) | `--state`, `--key-material`, `--import-token` | `OWN_KEY_STATE`, `OWN_KEY_KEY_MATERIAL`, `OWN_KEY_IMPORT_TOKEN` |
| `prepare` and `import`: trust anchor and expected organization id (mandatory unless `--non-production`) | `--trust-anchor`, `--expected-org-id` | `OWN_KEY_TRUST_ANCHOR`, `OWN_KEY_EXPECTED_ORG_ID` |
| Skip the production checks (local and STG only) | `--non-production` | none: a command line argument only |
| AWS account of the credentials (mandatory unless `--non-production`) | `--expected-aws-account` | `OWN_KEY_EXPECTED_AWS_ACCOUNT` |
| `discard`: state file of the preparation | `--state` | `OWN_KEY_STATE` |
| `reconcile`: grace period in seconds (default 160) | `--grace-seconds` | `OWN_KEY_GRACE_SECONDS` |

The default alias is `alias/own-key-<tenant>-<operationId>`.

**Database user.** In STG and PRO the tool connects with a **database user of its own**, not the master user of the
instance nor the Issuer's. Its task definition uses the same variable names as the Issuer (`SPRING_R2DBC_USERNAME`,
`SPRING_R2DBC_PASSWORD`, and `SPRING_FLYWAY_URL` for the URL) with the values of that user. In Dev it may keep using the
master user. The tool runs no migration (the Issuer does), so the user needs no `CREATE`; it needs:

| Object | Privileges |
|--------|------------|
| every tenant schema `<tenant>_issuer` | `USAGE` |
| `<tenant>_issuer.tenant_signing_config`, in every tenant schema | `SELECT`, `INSERT`, `UPDATE` |
| `public.tenant_registry` | `SELECT` |
| `public.signing_spki_reservation` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| `public.audit_outbox`, once the outbox sink is active | what the EUD-244 starter needs to stage an event (`INSERT`) |

```sql
GRANT USAGE ON SCHEMA <tenant>_issuer TO <tool user>;
GRANT SELECT, INSERT, UPDATE ON <tenant>_issuer.tenant_signing_config TO <tool user>;
GRANT SELECT ON public.tenant_registry TO <tool user>;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.signing_spki_reservation TO <tool user>;
```

**The provisioning of a new tenant must include its two grants** (`USAGE` on the schema and the privileges on its
`tenant_signing_config`). Without them the tool takes the tenant as not provisioned, and the check "is this key referenced
by any configuration" fails closed for every tenant: `import`, `discard` and `reconcile` end with exit 1 and touch no key
until the grants are given.

**Key policy.** `prepare` passes a JSON key policy to `CreateKey`, taken from one of two sources, never both (both
set is a usage error, exit 64):

- a file, `--key-policy <json file>` (or `OWN_KEY_KEY_POLICY` with its path), for an operator's workstation;
- the JSON itself in the environment variable `OWN_KEY_KEY_POLICY_JSON`, for a task that injects it from SSM Parameter
  Store (see *Running in production*). `prepare` is the only command that reads it; the others ignore it.

In production mode (the default) it refuses to create a key without one of them, so the key never gets the KMS default
policy, which delegates everything to the IAM of the account. With `--non-production` and neither it logs a warning and
uses the KMS default policy. Infra owns the content of the policy; the tool only checks that it is JSON. The file must be
UTF-8 without a byte order mark, and neither source may start with one: anything else is a usage error, because the
policy applied would not be the one hashed. `prepare` prints (`key policy  : sha256 <hex>`) and logs the **SHA-256 of
the UTF-8 bytes of the policy it passed to KMS**, never its content, so that it can be shown afterwards which policy
each key was created with; compare it with the hash of the policy infra approved. `--dry-run` creates no key and needs
none.

**State file.** `prepare` stores, next to the key and the certificate, a summary of its policy (production yes/no,
SHA-256 of the trust anchor, organization id). A successful `import` marks the state `importedAt`: it is consumed and
`import` refuses it afterwards, before any call to KMS. If the import was committed but the state file could not be marked (the exit code is still 0, because the onboarding is done), the tool prints a `WARNING` on stderr saying that the state file must not be used again and must be deleted: for a renewal nothing else refuses a second import of the same state, which would replace the configuration once more. Where the file system is POSIX the output directory `prepare` creates is
`0700` and every file `0600` (on Windows the defaults of the file system apply); the state file is rewritten through a
temporary file and an atomic move; and the token file the state names must be a plain file name starting with
`own-key-<tenant>-<operationId>`, otherwise it is not read. The operation id of the state must be a canonical UUID, as `prepare` writes it (it is kept in the configuration row and is the correlation id of the audit events): a state that carries anything else is refused. The tenant id `unknown` is refused: the Issuer takes it for a
request without tenant.

## Runbook notes

- **The database fails after `ImportKeyMaterial`.** If the database cannot be read or written once the key material is imported, the tool cannot prove that no configuration references the key, so it does **not** touch it (it logs `NOT touched ... Check it by hand`). The key may be left `ENABLED` and unreferenced, and neither `discard` (it refuses a key with material) nor `import` (it refuses an enabled key) will clean it. Clean it up by hand with the operation role: first check that no `tenant_signing_config` row of any tenant references its ARN (`own_key_kms_key_ref`, any status), then `kms:DisableKey` and `kms:ScheduleKeyDeletion` (and `kms:DeleteAlias` for its alias if it points to that key). The same applies if the outcome of the commit is unknown: check `tenant_signing_config` before doing anything.
- **Two runs of the same preparation (`import` or `discard`).** They take the same lock, so the second one ends with exit 1 (`another run is importing or discarding this preparation`) and touches nothing. Wait for the first to end and look at its result (and at the configuration of the tenant) before repeating. Once it holds the lock a run reads the state file again, so a copy read before the other run marked it is refused (`already imported`) or reported as already discarded.
- **The client times out on `ImportKeyMaterial` but KMS applied it.** The run does not know that its own import succeeded, so it finds the key `ENABLED`, takes it for a key it did not import and does **not** touch it. The key is left with material and unreferenced: clean it up by hand as in the first note.
- **`--db-url` must reach PostgreSQL directly, never through a pooler.** The lock of the operation is a session advisory lock (`pg_try_advisory_lock`) held on a connection of its own for the whole run. Behind a pooler in transaction mode (PgBouncer; check it with RDS Proxy) the lock may not belong to the session the tool thinks it does, and two runs could overlap. Use the RDS instance endpoint. The lock key is `(namespace, 32-bit hash of the operation id)`, with a namespace of its own, so it never collides with the transaction lock of a tenant; a collision between two operation ids only gives a false `another run is importing or discarding`, which fails safe.
- **The lock of the operation is lost during an `import`.** The session that holds the lock can end without the run knowing it (a cut connection, a server timeout, a failover); another run of the same preparation could then take the lock. So `import` checks on the lock's own connection that the server still shows the lock granted to that session (`pg_locks`) before `ImportKeyMaterial`, as the last step of the transaction that activates the configuration (a lost lock rolls it back) and before it disables and schedules the deletion of a key after a failure. If the lock is lost, the run commits nothing, does **not** touch the key, ends with exit 1 and logs `The lock of operation ... was lost ... NOT touched. Check it by hand`: look at the configuration of the tenant and at the key, and clean it up by hand as in the first note if no configuration references it.
- **Database timeouts.** Every transaction of the tool runs with `lock_timeout = 5s` and `statement_timeout = 30s`. A run that waits longer on a row or a lock (for example, a `reconcile` of the same tenant in the middle of its KMS calls) ends with exit 1 and a database error (SQLState `55P03` or `57014`) instead of hanging; `import` cleans up its new key as for any other failure before the commit. Repeat the run once the other one has ended.
- **`--dry-run` in production calls STS.** `--expected-aws-account` is mandatory in production for every command, including a dry run, so a dry run needs valid AWS credentials and network access to STS (`GetCallerIdentity`), even though it writes nothing.
- **File permissions on Windows.** The output directory and files are created `0700` and `0600` only where the file system is POSIX. On Windows they keep the ACLs they inherit: use an `--out-dir` inside the operator's profile, not a shared folder. On ECS do not write the output files to a shared volume (EFS, a bind mount shared with other tasks): use the ephemeral storage of the task. None of the files holds a private key, but they hold the state that `import` trusts.
- **The key of the same tenant is rejected right after a replacement.** Onboarding the key of a configuration that was just replaced ends with `KeyInUse` until `reconcile` retires the replaced key (grace period plus the next run); see the message of the rejection. If the message says instead that `reconcile` has **already handled** the configuration that holds the reservation, nothing will release it (the key is used by another tenant's configuration, or the row is gone): check `public.signing_spki_reservation` and the configurations that reference the key by hand.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Done (or `--help`). |
| 1 | Any other error (KMS, database, files). `reconcile` ends with 1 if any key could not be reconciled; the rest were. |
| 2 | Onboarding rejected by a validation, or the credentials belong to another account than `--expected-aws-account`: the reason is on stderr, nothing was put into service. |
| 64 | Usage error. |

Results go to stdout; logs and errors to stderr.

## Audit

Each created or replaced configuration, each key retired by `reconcile` and each rejected onboarding or discard produces a
`SigningConfigurationChanged` event (EUD-244 catalogue: `operation` Create, Replace or Retire, previous and new modality, certificate fingerprint, result
and, if not a success, the reason, which is always one of the catalogue vocabulary of the event: `PolicyDenied`, `InvalidKey`, `InvalidCertificate` or `KeyInUse` (Denied) and `ProviderUnavailable` (Failure); actor = the caller ARN;
duration). A rejection because the tenant is not in `public.tenant_registry` or is not active is audited like any other, with the tenant id as given (the audit API keeps the events of an unknown tenant as rejected events of its own), and also leaves a warn log line. The event is staged in the same transaction as the change; a rejection is recorded in a transaction of its
own. Until the outbox of EUD-244 exists, `LoggingSigningConfigurationAuditSink` writes it as a JSON line to the
logger `es.in2.issuer.backend.signing.onboarding.audit` after the commit. The event holds no secrets and no key
ARN. To use the outbox, implement `SigningConfigurationAuditSink.stage` (an insert on the given connection, or the
EUD-244 starter); nothing else changes.

`Retire` (by `reconcile`): `Success` when the key was disabled and its deletion scheduled (or was already), `Denied` with
`KeyInUse` when an active configuration references the key and it is left alone, `Failure` (recorded in its own transaction) with reason `ProviderUnavailable`, in both sinks, when it could not be retired. It has no new modality and no certificate; the
correlation id is the operation id of the onboarding that activated the withdrawn configuration
(`own_key_operation_id`, which `import` and a renewal keep in the row), the same id as the correlation id of its `Create`
or `Replace` event, so all the events of one key can be joined; it is empty for a row the tool did not write (seeds, the
bash tool, rows written by hand). A `discard` is a `Retire` too: `Success` when it retired the key (recorded in its own transaction, with the operation id as correlation id, right after the key is retired and before the state file is marked, so a failure marking the file does not lose it; a key that was already pending deletion or gone leaves no event, because nothing was retired), `Denied` when it was refused and `Failure` when another run held the lock of the operation. If recording the event fails, the discard still stands and the failure is logged. No event holds a key
ARN.

**`Failure` means "the operation could not be completed".** `ProviderUnavailable` is the only `Failure` reason of
`SigningConfigurationChanged` in the catalogue (2.2.0), so it is used for any failure that is not a rejection, whatever
its cause (KMS, STS, the database, a key in an unexpected state, a lock held by another run): read it as *the operation
could not be completed*, and look at the log of the run for the cause. A `Create` or `Replace` `Failure` is recorded, in
its own transaction, when:

- `import` of a new key fails for any reason but a rejection from `ImportKeyMaterial` on (the key is then cleaned up as
  described above); the reason may be the failure of `ImportKeyMaterial` itself;
- a renewal fails for any reason but a rejection;
- `import` finds the lock of its operation held by another run. Whether it is a `Create` or a `Replace` (and the
  previous modality) is read from the tenant's active configuration at that moment; a renewal is always a `Replace`.

When the database did not confirm the commit (the outcome is unknown) no `Failure` is recorded: the `Success` may already
be committed. A run with the credentials of **another AWS account** than `--expected-aws-account` leaves no event (it
ends before anything is opened): it logs a `WARN` with the account it was given and the account STS reports.

**With the `log` sink the audit trail is not acceptable for production.** It is a log line written after the commit,
with no guarantee of delivery or retention. Until the outbox sink is active (below), do not use the tool in production for
anything that must be auditable.

`activated_by` and `withdrawn_by` hold the caller ARN from STS `GetCallerIdentity`, never free text.

## Audit sink: the outbox of the EUD-244 starter (ready, not active)

`OWN_KEY_AUDIT_SINK=log` (the default) writes the event to the audit logger, as above. `OWN_KEY_AUDIT_SINK=outbox`
stages it in `public.audit_outbox` with the EUD-244 audit starter (`com.eudistack:auditoria-spring-boot-starter`),
in the same transaction as the configuration change, and the Issuer's dispatcher sends it later. **The outbox mode
exists but is inactive:** the default build does not include the starter, because the Issuer cannot resolve it from
GitHub Packages yet (no authentication in CI or in the Docker build). With `outbox` in a build without it, the tool
ends with exit code 1 and a message saying that the build lacks the audit starter.

How it works. The tool's transactions are Spring transactions (`DataSourceTransactionManager`) on one
`DataSource`, so whatever the sink stages on that data source joins them: the starter refuses to stage outside a
transaction. In outbox mode the tool starts a minimal non-web Spring context
(`OutboxAuditConfiguration`) that imports only the starter's own auto-configurations for the properties, the context
accessor and the publisher, plus the two beans the starter only creates for servlet applications
(`JdbcAuditOutboxSchema`, `JdbcOutboxStore`). Publisher on, **dispatcher off** (the tool never sends events),
`auditoria.source=issuer`; the event's own source is `signing`. Nothing of the Issuer's context (R2DBC, Flyway,
WebFlux, its beans, its `application.yml`) is loaded. The tenant and the actor (the caller ARN) come from
`AuditContexts.system(tenant, callerArn, operationId)`; a rejected onboarding is staged in a transaction of its own,
also when the tenant is unknown. `details` are `operation`, `previous_modality`, `new_modality` and
`signing_certificate` (`sha256:<hex>` of the leaf certificate); the resource is `signing-configuration:<tenant>`.

Where the code is. The sink, the context and their tests are in the opt-in source sets `src/audit-starter/main/java`
and `src/audit-starter/test/java`, compiled only with `-PauditStarter`, which also adds the dependency
`com.eudistack:auditoria-spring-boot-starter:0.1.0` and the repositories `mavenLocal()` and GitHub Packages
(credentials from `GITHUB_ACTOR`/`GITHUB_TOKEN` or `gpr.user`/`gpr.token`). Without the flag the build has no extra
repository, dependency or source. The main code has no starter types: it loads
`...onboarding.audit.OutboxAuditSinkFactory` by name.

Tested against the starter **v0.1.0 built locally from its tag** and published to Maven Local
(`git clone --branch v0.1.0 https://github.com/in2workspace/eudistack-platform-audit-starter`,
`./gradlew publishToMavenLocal`), not downloaded from GitHub Packages. Run them with
`./gradlew check -PauditStarter`.

Activating it for good:

1. In `build.gradle`, remove the `if (project.hasProperty('auditStarter'))` condition, so the source sets, the
   dependency and the repositories are always there.
2. Set `OWN_KEY_AUDIT_SINK=outbox` in the environment of the tool's task.
3. Prerequisites outside this repository's code: read access to the package for the Issuer repository; CI
   authentication to GitHub Packages (the shared workflows that build the Issuer, and the SHA of those workflows the
   Issuer pins); and a build secret for the Dockerfile, which compiles inside the image.
