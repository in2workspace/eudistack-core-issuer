# Credential Profile Engine — Spec & Implementation Status

> **Status**: Implemented
> **Last updated**: 2026-03

---

## Overview

Credentials are defined by **JSON profile files** in the classpath. Each profile is the **single source of truth** for:

1. **Building** W3C VCDM credentials (context, types, validity, subject extraction, credentialSubject strategy)
2. **Generating** `/.well-known/openid-credential-issuer` metadata (OID4VCI 1.0 Final)
3. **SD-JWT** selective disclosure configuration
4. **Input schema validation** (JSON Schema file reference per credential type)

Adding a new credential type = **only a new JSON profile file**. No Java code changes.

---

## Directory layout

```
src/main/resources/credentials/
├── profiles/
│   ├── lear-credential-employee.json          # SD-JWT (dc+sd-jwt) — configId: LEARCredentialEmployee
│   ├── lear-credential-employee-w3c-vcdm-2.json  # W3C JWT — configId: LEARCredentialEmployeeW3C
│   ├── lear-credential-machine.json           # SD-JWT — configId: LEARCredentialMachine
│   ├── lear-credential-machine-w3c-vcdm-2.json   # W3C JWT — configId: LEARCredentialMachineW3C
│   └── label-credential.json                  # W3C JWT — configId: gx:LabelCredential
└── schemas/
    └── gxLabelCredential.jwt_vc_json.v1.json  # JSON Schema for LabelCredential input
```

---

## Profile field reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_configuration_id` | `string` | Yes | Unique ID per OID4VCI. Primary key for all lookups. |
| `credential_format` | `string` | Yes | `"jwt_vc_json"` or `"dc+sd-jwt"` |
| `scope` | `string` | No | OAuth scope for this credential |
| `credential_definition.context` | `string[]` | Yes | JSON-LD `@context` URLs |
| `credential_definition.type` | `string[]` | Yes | VC types (first non-"VerifiableCredential" = logical type name) |
| `cryptographic_binding_methods_supported` | `string[]` | Yes | e.g. `["did:key"]`, `[]` for no binding |
| `credential_signing_alg_values_supported` | `string[]` | Yes | e.g. `["ES256"]` |
| `proof_types_supported` | `map` | Yes | Proof type → signing algs. `{}` for no proof required. |
| `credential_metadata.display` | `object[]` | No | OID4VCI display info (name, locale, description) |
| `credential_metadata.claims` | `object[]` | No | OID4VCI claim paths + display labels |
| `validity_days` | `int` | Yes | Auto-calculated validity. `0` = read validFrom/validUntil from payload |
| `issuer_type` | `enum` | Yes | `"DETAILED"` (object issuer with id/name/…) or `"SIMPLE"` (string DID only) |
| `cnf_required` | `boolean` | Yes | JWT must include `cnf` for holder binding |
| `description` | `string` | No | Included verbatim in the VC body if set |
| `credential_subject_strategy` | `string` | No | `"direct"` or omit/`"mandate"` (default). See below. |
| `json_schema` | `string` | No | Filename in `credentials/schemas/` for input validation |
| `subject_extraction` | `object` | No | How to derive the display subject name |
| `organization_extraction` | `object` | No | How to derive the organization identifier |
| `sd_jwt` | `object` | No | SD-JWT config (`vct`, `sd_alg`, `sd_claims`) |

### `credential_subject_strategy`

Controls how `GenericCredentialBuilder` wraps the incoming payload into `credentialSubject`:

| Value | Behavior | Use case |
|-------|----------|----------|
| `"mandate"` (default) | `credentialSubject = { mandate: payload }` | LEARCredential* — payload is the mandate object |
| `"direct"` | `credentialSubject = payload.credentialSubject` | LabelCredential — payload is the full credential; extract its credentialSubject directly |

### `subject_extraction`

| Field | Description |
|-------|-------------|
| `strategy` | `"concat"` (join fields with separator) or `"field"` (first non-blank field) |
| `fields` | Dot-paths relative to the **raw payload** (e.g. `"mandate.mandatee.firstName"`, `"credentialSubject.id"`) |
| `separator` | Join separator for `concat` strategy (default: `" "`) |

### `organization_extraction`

| Field | Description |
|-------|-------------|
| `strategy` | `"field"` (from payload dot-path) or `"session"` (from `AccessTokenService.getOrganizationIdFromCurrentSession()`) |
| `field` | Dot-path for `field` strategy (e.g. `"mandate.mandator.organizationIdentifier"`) |

### `sd_jwt`

| Field | Description |
|-------|-------------|
| `vct` | Verifiable Credential Type URI (SD-JWT `vct` header claim) |
| `sd_alg` | Hash algorithm for disclosures (e.g. `"sha-256"`) |
| `sd_claims` | Dot-paths of claims to make selectively disclosable |

---

## Java components

### `CredentialProfile` (record)

**Path**: `shared/domain/model/dto/credential/profile/CredentialProfile.java`

Jackson-annotated record. Nested records: `CredentialDefinition`, `ProofTypeConfig`, `CredentialMetadata`, `DisplayInfo`, `ClaimDefinition`, `SubjectExtraction`, `OrganizationExtraction`, `SdJwtConfig`, `IssuerType` enum.

Key derived method: `credentialType()` — returns the first non-"VerifiableCredential" type from `credential_definition.type`.

### `CredentialProfileRegistry` (component)

**Path**: `shared/infrastructure/config/CredentialProfileRegistry.java`

Loads all `classpath:credentials/profiles/*.json` at startup. Two lookup maps:

| Method | Key | Example |
|--------|-----|---------|
| `getByConfigurationId(id)` | `credential_configuration_id` | `"LEARCredentialEmployee"` |
| `getByCredentialType(type)` | Logical type from `credential_definition.type` | `"LEARCredentialEmployee"` |

Fail-fast: throws on duplicate IDs or missing required fields.

> **Note**: `getByEnumName()` was removed when `CredentialType` enum was deleted. All lookups are now by `credential_configuration_id` (primary) or logical type (secondary fallback).

### `GenericCredentialBuilder` (component)

**Path**: `shared/domain/util/factory/GenericCredentialBuilder.java`

Profile-driven credential operations:

| Method | Purpose |
|--------|---------|
| `buildCredential(profile, procedureId, payload, status, opMode, email)` | Build W3C VC as JSON. Branches on `credential_subject_strategy`. |
| `bindSubjectId(json, subjectDid)` | Sets `credentialSubject.id` (holder binding after proof validation) |
| `bindIssuer(profile, json, procedureId, email)` | Binds DETAILED or SIMPLE issuer depending on `issuer_type` |
| `buildJwtPayload(profile, json, cnf)` | Builds JWT `{jti, iss, sub, iat, exp, nbf, vc, cnf?}` |

---

## JSON Schema validation

Each profile can reference a JSON Schema file via `json_schema`. The file is stored in `credentials/schemas/` and named by convention: `{credentialType}.{format}.v{n}.json`.

**Current schemas:**

| File | Validates |
|------|-----------|
| `gxLabelCredential.jwt_vc_json.v1.json` | LabelCredential input payload (`credentialSubject` + `validFrom` + `validUntil`) |

**Integration point (pending):** The registry can load the schema at startup and expose it via `CredentialProfile.jsonSchema()`. Validation would be called in `CredentialIssuanceWorkflowImpl` before building the credential. See implementation task below.

### Pending: schema validation step

```java
// In CredentialIssuanceWorkflowImpl, before buildCredential():
if (profile.jsonSchema() != null) {
    jsonSchemaValidator.validate(profile.jsonSchema(), payload);
}
```

`JsonSchemaValidator` would use `networknt/json-schema-validator` (already common in Spring ecosystems) to load the schema from classpath and validate the incoming `JsonNode`.

---

## How to add a new credential type

### Step 1 — Create the JSON profile

```json
{
  "credential_configuration_id": "MyNewCredential",
  "credential_format": "jwt_vc_json",
  "scope": "my_new_credential",

  "credential_definition": {
    "context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://example.com/.well-known/credentials/my-new/v1"
    ],
    "type": ["VerifiableCredential", "MyNewCredential"]
  },

  "cryptographic_binding_methods_supported": ["did:key"],
  "credential_signing_alg_values_supported": ["ES256"],
  "proof_types_supported": {
    "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
  },

  "credential_metadata": {
    "display": [{ "name": "My New Credential", "locale": "en" }],
    "claims": [
      { "path": ["credentialSubject", "mandate", "mandatee", "name"],
        "display": [{ "name": "Name", "locale": "en" }] }
    ]
  },

  "validity_days": 365,
  "issuer_type": "DETAILED",
  "cnf_required": true,
  "description": "My new credential description",

  "subject_extraction": {
    "strategy": "field",
    "fields": ["mandate.mandatee.name"]
  },
  "organization_extraction": {
    "strategy": "field",
    "field": "mandate.mandator.organizationIdentifier"
  }
}
```

### Step 2 — (Optional) Create the JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "myNewCredential.jwt_vc_json.v1",
  "type": "object",
  "required": ["mandatee", "mandator"],
  "properties": { ... }
}
```

Reference it in the profile: `"json_schema": "myNewCredential.jwt_vc_json.v1.json"`.

### Step 3 — Add issuance policy (if non-LEAR type)

If the new credential type needs a different authorization rule, add a `case` in `IssuancePdpServiceImpl.authorize()`.

### Step 4 — Done

The application will automatically:
- Load the profile at startup
- Expose it in `/.well-known/openid-credential-issuer`
- Build credentials via `GenericCredentialBuilder`
- Sign via `CredentialSignerWorkflowImpl` (profile-based path)

---

## Legacy factory migration status

| Factory | Status | Notes |
|---------|--------|-------|
| `LEARCredentialEmployeeFactory` | Dead code (fallback only) | Profile-based path always matched first |
| `LEARCredentialMachineFactory` | Dead code (fallback only) | Same |
| `LabelCredentialFactory` | Dead code (fallback only) | `credential_subject_strategy: "direct"` enables generic path |

**To remove legacy factories (separate PR):**
1. Delete `LEARCredentialEmployeeFactory`, `LEARCredentialMachineFactory`, `LabelCredentialFactory`
2. Delete associated JWT payload records (`LEARCredentialEmployeeJwtPayload`, etc.)
3. Remove fallback `if/else` and `switch` blocks from `CredentialFactory` and `CredentialSignerWorkflowImpl`
4. Remove `LabelCredentialJwtPayload` DTO and associated test

---

## OID4VCI 1.0 Final metadata (auto-generated)

`CredentialIssuerMetadataServiceImpl` reads from the registry — no manual mapping needed:

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "...",
  "credential_configurations_supported": {
    "LEARCredentialEmployee": {
      "format": "dc+sd-jwt",
      "scope": "lear_credential_employee",
      "cryptographic_binding_methods_supported": ["did:key"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } },
      "credential_definition": { "type": ["VerifiableCredential", "LEARCredentialEmployee"] }
    }
  }
}
```
