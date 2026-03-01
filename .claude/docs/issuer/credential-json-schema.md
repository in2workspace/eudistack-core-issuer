# JSON Schema-Driven Credential Definitions

> **Status**: Implemented (Block A complete)

## Overview

Credentials are defined by **JSON profile files** stored in the classpath. Each profile is the **single source of truth** for:

1. **Building** W3C VCDM credentials (context, types, validity, subject extraction)
2. **Generating** `/.well-known/openid-credential-issuer` metadata (OID4VCI 1.0 Final format)
3. **SD-JWT** selective disclosure configuration (Block B prep)

Adding a new credential type requires **only a new JSON file** — no Java code changes, no recompilation.

## Architecture

```
src/main/resources/credentials/profiles/
├── lear-credential-employee.json
├── lear-credential-machine.json
└── label-credential.json
```

```
                    JSON Profile File
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
     CredentialProfileRegistry
     (loads all at startup)
              │
    ┌─────────┼─────────────┐
    ▼                       ▼
GenericCredentialBuilder   CredentialIssuerMetadataServiceImpl
(build, bind, sign)       (auto-generate OID4VCI metadata)
```

## How to Add a New Credential Type

### Step 1: Create the JSON profile

Create a new file in `src/main/resources/credentials/profiles/`, e.g. `student-id.json`:

```json
{
  "credential_configuration_id": "StudentIdCredential",
  "format": "jwt_vc_json",
  "scope": "student_id",

  "credential_definition": {
    "context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://example.edu/.well-known/credentials/student-id/v1"
    ],
    "type": ["VerifiableCredential", "StudentIdCredential"]
  },

  "cryptographic_binding_methods_supported": ["did:key"],
  "credential_signing_alg_values_supported": ["ES256"],
  "proof_types_supported": {
    "jwt": {
      "proof_signing_alg_values_supported": ["ES256"]
    }
  },

  "credential_metadata": {
    "display": [
      {
        "name": "Student ID Credential",
        "locale": "en",
        "description": "University student identification credential"
      }
    ],
    "claims": [
      {
        "path": ["credentialSubject", "mandate", "mandatee", "studentName"],
        "display": [{ "name": "Student Name", "locale": "en" }]
      },
      {
        "path": ["credentialSubject", "mandate", "mandatee", "studentId"],
        "display": [{ "name": "Student ID", "locale": "en" }]
      },
      {
        "path": ["credentialSubject", "mandate", "mandator", "organizationIdentifier"],
        "display": [{ "name": "University", "locale": "en" }]
      }
    ]
  },

  "validity_days": 365,
  "issuer_type": "DETAILED",
  "cnf_required": true,
  "description": "University student identification credential",

  "subject_extraction": {
    "strategy": "concat",
    "fields": ["mandate.mandatee.studentName"],
    "separator": " "
  },
  "organization_extraction": {
    "strategy": "field",
    "field": "mandate.mandator.organizationIdentifier"
  }
}
```

### Step 2: Add enum to `CredentialType`

Add the new type to `CredentialType.java`:

```java
public enum CredentialType {
    LEAR_CREDENTIAL_EMPLOYEE("LEARCredentialEmployee"),
    LEAR_CREDENTIAL_MACHINE("LEARCredentialMachine"),
    LABEL_CREDENTIAL("gx:LabelCredential"),
    STUDENT_ID("StudentIdCredential");  // NEW
    // ...
}
```

The `typeId` must match `credential_configuration_id` in the JSON profile. This enables the `byEnumName` lookup used by `CredentialSignerWorkflowImpl`.

### Step 3: Done

The application will:
- Load the profile at startup via `CredentialProfileRegistry`
- Build credentials via `GenericCredentialBuilder`
- Expose metadata via `/.well-known/openid-credential-issuer`

No factory classes, no dispatcher changes, no metadata builder changes.

## Profile Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_configuration_id` | `string` | Yes | Unique identifier. Must match `CredentialType.getTypeId()` |
| `format` | `string` | Yes | `"jwt_vc_json"` (or `"dc+sd-jwt"` in Block B) |
| `scope` | `string` | No | OAuth scope for this credential |
| `credential_definition.context` | `string[]` | Yes | JSON-LD `@context` URLs |
| `credential_definition.type` | `string[]` | Yes | VC types (first non-"VerifiableCredential" = credential type name) |
| `cryptographic_binding_methods_supported` | `string[]` | No | e.g. `["did:key"]`, `[]` for no binding |
| `credential_signing_alg_values_supported` | `string[]` | No | e.g. `["ES256"]` |
| `proof_types_supported` | `map` | No | Proof type configs. `{}` for no proof required |
| `credential_metadata.display` | `object[]` | No | OID4VCI display info (name, locale, description) |
| `credential_metadata.claims` | `object[]` | No | OID4VCI claim paths + display |
| `validity_days` | `int` | Yes | Auto-calculated validity. `0` = use payload dates |
| `issuer_type` | `enum` | Yes | `"DETAILED"` (object issuer) or `"SIMPLE"` (string issuer) |
| `cnf_required` | `boolean` | Yes | Whether JWT payload must include `cnf` |
| `description` | `string` | No | Included in VC body if set |
| `subject_extraction` | `object` | No | How to derive the "subject" display name |
| `organization_extraction` | `object` | No | How to derive the organization identifier |
| `sd_jwt` | `object` | No | SD-JWT config (Block B) |

### `subject_extraction`

| Field | Description |
|-------|-------------|
| `strategy` | `"concat"` (join fields) or `"field"` (first field) |
| `fields` | Dot-path list relative to payload (e.g. `"mandate.mandatee.firstName"`) |
| `separator` | Join separator for `concat` strategy (default: `" "`) |

### `organization_extraction`

| Field | Description |
|-------|-------------|
| `strategy` | `"field"` (from payload) or `"session"` (from `AccessTokenService`) |
| `field` | Dot-path for `field` strategy (e.g. `"mandate.mandator.organizationIdentifier"`) |

### `sd_jwt` (Block B prep)

| Field | Description |
|-------|-------------|
| `vct` | Verifiable Credential Type URI |
| `sd_alg` | Hash algorithm for SD-JWT (e.g. `"sha-256"`) |
| `sd_claims` | Dot-paths of claims to make selectively disclosable |

## Java Components

### `CredentialProfile` (record)

**Location**: `shared/domain/model/dto/credential/profile/CredentialProfile.java`

Jackson-annotated record loaded from JSON. Contains nested records:
- `CredentialDefinition` (context, type)
- `ProofTypeConfig` (signing algs)
- `CredentialMetadata` (display, claims) — maps 1:1 to OID4VCI metadata output
- `SubjectExtraction`, `OrganizationExtraction`
- `SdJwtConfig`
- `IssuerType` enum (DETAILED, SIMPLE)

The `credentialType()` method derives the VC type name from `credential_definition.type`, skipping "VerifiableCredential".

### `CredentialProfileRegistry` (component)

**Location**: `shared/infrastructure/config/CredentialProfileRegistry.java`

Loads all `classpath:credentials/profiles/*.json` at startup. Provides three lookup maps:

| Method | Key | Example |
|--------|-----|---------|
| `getByConfigurationId(id)` | `credential_configuration_id` | `"LEARCredentialEmployee"` |
| `getByCredentialType(type)` | Derived type name | `"LEARCredentialEmployee"` |
| `getByEnumName(name)` | `CredentialType` enum name | `"LEAR_CREDENTIAL_EMPLOYEE"` |
| `getAllProfiles()` | All, keyed by config ID | — |

Fail-fast: throws `IllegalStateException` on duplicate IDs, types, or missing config IDs.

### `GenericCredentialBuilder` (component)

**Location**: `shared/domain/util/factory/GenericCredentialBuilder.java`

Profile-driven credential operations:

| Method | Purpose | Replaces |
|--------|---------|----------|
| `buildCredential(profile, procedureId, payload, status, opMode, email)` | Build W3C VC as JSON | `mapAndBuild*()` methods |
| `bindSubjectId(json, subjectDid)` | Set `credentialSubject.id` | `bindCryptographicCredentialSubjectId()` |
| `bindIssuer(profile, json, procedureId, email)` | Bind DetailedIssuer or SimpleIssuer | `mapCredentialAndBindIssuer*()` |
| `buildJwtPayload(profile, json, cnf)` | Build JWT `{jti, iss, sub, iat, exp, nbf, vc, cnf?}` | `build*JwtPayload()` |

## OID4VCI 1.0 Final Metadata

The `credential_metadata` section in each profile maps **directly** to the OID4VCI 1.0 Final format. `CredentialIssuerMetadataServiceImpl` auto-generates from the registry:

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/oid4vci/v1/credential",
  "credential_configurations_supported": {
    "LEARCredentialEmployee": {
      "format": "jwt_vc_json",
      "scope": "lear_credential_employee",
      "cryptographic_binding_methods_supported": ["did:key"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
      },
      "credential_metadata": {
        "display": [{
          "name": "LEAR Credential Employee",
          "locale": "en",
          "description": "Verifiable Credential for employees of an organization"
        }],
        "claims": [
          { "path": ["credentialSubject", "mandate", "mandatee", "firstName"],
            "display": [{"name": "First Name", "locale": "en"}] }
        ]
      }
    }
  }
}
```

## Migration Status

The old factories (`LEARCredentialEmployeeFactory`, `LEARCredentialMachineFactory`, `LabelCredentialFactory`) are kept as **fallbacks** in `CredentialFactory` and `CredentialSignerWorkflowImpl`. The generic path is tried first; if a profile is found, the old factory is bypassed.

To remove the old factories (separate PR):
1. Delete `LEARCredentialEmployeeFactory`, `LEARCredentialMachineFactory`, `LabelCredentialFactory`
2. Delete associated JWT payload records
3. Remove fallback `if/else` and `switch` blocks from `CredentialFactory` and `CredentialSignerWorkflowImpl`
