# Plan: JSON Schema-Driven Credential Definitions

## Current State: Hardcoded Factories

Credentials are defined as Java records with factory classes:

```
CredentialFactory (dispatcher)
├── LEARCredentialEmployeeFactory  → LEARCredentialEmployee record
├── LEARCredentialMachineFactory   → LEARCredentialMachine record
└── LabelCredentialFactory         → LabelCredential record
```

### Problems

1. **Adding a new credential type requires**:
   - New Java record (e.g., `StudentIdCredential.java`)
   - New Factory class (e.g., `StudentIdCredentialFactory.java`)
   - New `else if` branch in `CredentialFactory.mapCredentialIntoACredentialProcedureRequest()`
   - New `case` in `CredentialFactory.bindCryptographicCredentialSubjectId()`
   - New `case` in `CredentialFactory.mapCredentialBindIssuerAndUpdateDB()`
   - Recompilation and redeployment

2. **Context URL parsing is fragile** (from `LEARCredentialEmployeeFactory.java:82-108`):
   ```java
   if (learCredential.contains("https://trust-framework.dome-marketplace.eu/...")) {
       // parse as v1
   } else if (learCredential.contains("https://www.dome-marketplace.eu/2025/...")) {
       // parse as v2 (with TMF field removal)
   } else if (learCredential.contains(EUDISTACK_CONTEXT)) {
       // parse as v3
   } else {
       throw new InvalidCredentialFormatException("Invalid credential format");
   }
   ```

3. **Metadata is disconnected from credential definitions**:
   - `CredentialIssuerMetadata` builds `credential_configurations_supported` separately from the factories
   - Uses draft format (`credential_definition.type[]`) instead of OID4VCI 1.0 Final (`credential_metadata.claims[].path[]`)

## Target State: JSON Schema-Driven

### Credential Profile JSON File

Each credential type is defined by a JSON file:

```
src/main/resources/credentials/profiles/
├── lear-credential-employee.json
├── lear-credential-machine.json
├── label-credential.json
└── student-id.json              # New types = new file, no code changes
```

### Profile Schema

```json
{
  "credential_configuration_id": "eu.europa.ec.eudi.lear-employee_jwt_vc_json",
  "format": "jwt_vc_json",
  "scope": "eu.europa.ec.eudi.lear-employee",

  "credential_definition": {
    "context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
    ],
    "type": ["VerifiableCredential", "LEARCredentialEmployee"]
  },

  "display": [
    {
      "name": "LEAR Credential Employee",
      "locale": "en",
      "description": "Legal Entity Appointed Representative Credential for an employee"
    }
  ],

  "cryptographic_binding_methods_supported": ["jwk"],
  "credential_signing_alg_values_supported": ["ES256"],
  "proof_types_supported": {
    "jwt": {
      "proof_signing_alg_values_supported": ["ES256"]
    }
  },

  "claims": [
    {
      "path": ["credentialSubject", "mandate", "mandatee", "firstName"],
      "display": [{ "name": "First Name", "locale": "en" }],
      "mandatory": true,
      "source_field": "mandatee.firstName",
      "selective_disclosure": true
    },
    {
      "path": ["credentialSubject", "mandate", "mandatee", "lastName"],
      "display": [{ "name": "Last Name", "locale": "en" }],
      "mandatory": true,
      "source_field": "mandatee.lastName",
      "selective_disclosure": true
    },
    {
      "path": ["credentialSubject", "mandate", "mandatee", "email"],
      "display": [{ "name": "Email", "locale": "en" }],
      "mandatory": true,
      "source_field": "mandatee.email",
      "selective_disclosure": true
    },
    {
      "path": ["credentialSubject", "mandate", "mandator", "organizationIdentifier"],
      "display": [{ "name": "Organization", "locale": "en" }],
      "mandatory": true,
      "source_field": "mandator.organizationIdentifier",
      "selective_disclosure": false
    },
    {
      "path": ["credentialSubject", "mandate", "power"],
      "display": [{ "name": "Powers", "locale": "en" }],
      "mandatory": true,
      "source_field": "power",
      "selective_disclosure": false
    }
  ],

  "validity_days": 365,

  "sd_jwt": {
    "vct": "urn:eu.europa.ec.eudi:lear-employee:1",
    "sd_claims": ["credentialSubject.mandate.mandatee.firstName",
                   "credentialSubject.mandate.mandatee.lastName",
                   "credentialSubject.mandate.mandatee.email"]
  }
}
```

### Additional Format Configuration

When the same credential type should be offered in multiple formats:

```
credentials/profiles/
├── lear-credential-employee.json              # Base definition (jwt_vc_json)
└── lear-credential-employee.sd-jwt.json       # SD-JWT variant
```

The SD-JWT variant:

```json
{
  "credential_configuration_id": "eu.europa.ec.eudi.lear-employee_dc+sd-jwt",
  "format": "dc+sd-jwt",
  "extends": "lear-credential-employee",
  "sd_jwt": {
    "vct": "urn:eu.europa.ec.eudi:lear-employee:1",
    "sd_alg": "sha-256"
  }
}
```

## New Java Components

### CredentialProfile (value object)

```java
public record CredentialProfile(
    String credentialConfigurationId,
    String format,                          // "jwt_vc_json" or "dc+sd-jwt"
    String scope,
    CredentialDefinition credentialDefinition,
    List<DisplayInfo> display,
    Set<String> cryptographicBindingMethodsSupported,
    Set<String> credentialSigningAlgValuesSupported,
    Map<String, ProofTypeConfig> proofTypesSupported,
    List<ClaimDefinition> claims,
    int validityDays,
    SdJwtConfig sdJwt                       // null for jwt_vc_json format
) {
    public record CredentialDefinition(List<String> context, List<String> type) {}
    public record DisplayInfo(String name, String locale, String description) {}
    public record ClaimDefinition(
        List<String> path,
        List<DisplayInfo> display,
        boolean mandatory,
        String sourceField,
        boolean selectiveDisclosure
    ) {}
    public record SdJwtConfig(String vct, String sdAlg, List<String> sdClaims) {}
    public record ProofTypeConfig(Set<String> proofSigningAlgValuesSupported) {}
}
```

### CredentialProfileRegistry

```java
@Component
public class CredentialProfileRegistry {

    private final Map<String, CredentialProfile> profiles;  // keyed by credential_configuration_id

    public CredentialProfileRegistry(ObjectMapper objectMapper, ResourcePatternResolver resolver) {
        // Load all JSON files from classpath:credentials/profiles/*.json at startup
        this.profiles = loadProfiles(objectMapper, resolver);
    }

    public CredentialProfile getProfile(String credentialConfigurationId) { ... }
    public Map<String, CredentialProfile> getAllProfiles() { ... }
    public List<CredentialProfile> getProfilesByType(String credentialType) { ... }
}
```

### GenericCredentialBuilder

```java
@Component
@RequiredArgsConstructor
public class GenericCredentialBuilder {

    private final CredentialProfileRegistry registry;
    private final ObjectMapper objectMapper;

    /**
     * Builds a credential JSON from a profile + subject data.
     * Replaces LEARCredentialEmployeeFactory, LEARCredentialMachineFactory, LabelCredentialFactory.
     */
    public Mono<String> buildCredential(
            String credentialConfigurationId,
            JsonNode subjectData,
            CredentialStatus credentialStatus,
            Issuer issuer,
            String subjectDid,
            Map<String, Object> cnf) {

        CredentialProfile profile = registry.getProfile(credentialConfigurationId);

        return switch (profile.format()) {
            case "jwt_vc_json" -> buildW3cVcdm(profile, subjectData, credentialStatus, issuer, subjectDid, cnf);
            case "dc+sd-jwt"  -> buildSdJwt(profile, subjectData, issuer, subjectDid, cnf);
            default -> Mono.error(new UnsupportedOperationException("Format: " + profile.format()));
        };
    }

    private Mono<String> buildW3cVcdm(CredentialProfile profile, JsonNode subjectData, ...) {
        // Builds the same JSON structure as current factories
        // Uses profile.credentialDefinition().context() and .type()
        // Maps subjectData using profile.claims()[].sourceField → path
    }

    private Mono<String> buildSdJwt(CredentialProfile profile, JsonNode subjectData, ...) {
        // See sd-jwt-implementation.md
    }
}
```

### Updated Metadata Generation

```java
@Component
@RequiredArgsConstructor
public class CredentialIssuerMetadataServiceImpl implements CredentialIssuerMetadataService {

    private final CredentialProfileRegistry registry;
    private final AppConfig appConfig;

    @Override
    public Mono<CredentialIssuerMetadata> generateMetadata() {
        // Auto-generate from registry — no more manual metadata building
        Map<String, CredentialConfiguration> configs = registry.getAllProfiles().entrySet().stream()
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                e -> mapProfileToConfiguration(e.getValue())
            ));

        return Mono.just(CredentialIssuerMetadata.builder()
            .credentialIssuer(appConfig.getIssuerBackendUrl())
            .credentialEndpoint(appConfig.getIssuerBackendUrl() + "/oid4vci/v1/credential")
            // ... other endpoints ...
            .credentialConfigurationsSupported(configs)
            .build());
    }
}
```

## Migration Strategy

### Step 1: Create infrastructure (no behavior change)
- Create `CredentialProfile` record
- Create `CredentialProfileRegistry` that loads from JSON
- Create JSON profiles for existing 3 credential types
- Write tests that validate JSON profiles match current factory output

### Step 2: Create GenericCredentialBuilder for jwt_vc_json
- Implement `buildW3cVcdm()` method
- **Regression test**: For each credential type, compare output of old Factory vs new GenericCredentialBuilder
- The outputs MUST be byte-for-byte identical (same JSON structure, same field order)

### Step 3: Wire GenericCredentialBuilder into existing flow
- Update `CredentialFactory` to delegate to `GenericCredentialBuilder` when a profile exists
- Keep old factories as fallback (feature flag or config)
- Run full test suite

### Step 4: Update metadata generation
- Update `CredentialIssuerMetadata` model to include OID4VCI 1.0 Final fields
- Generate metadata from `CredentialProfileRegistry`
- Backwards compatible: existing fields still present

### Step 5: Remove old factories (when stable)
- Delete `LEARCredentialEmployeeFactory`, `LEARCredentialMachineFactory`, `LabelCredentialFactory`
- Delete `CredentialFactory` dispatcher
- Update tests

## Retrocompatibility

| Concern | Strategy |
|---------|----------|
| Existing credentials in DB | `credential_decoded` JSON unchanged — same structure |
| Wallets expecting `jwt_vc_json` | Same JWT structure produced |
| Metadata consumers | Existing fields preserved, new fields added |
| Backoffice issuance API | `PreSubmittedCredentialDataRequest.schema()` maps to `credentialConfigurationId` |
| Tests | Byte-for-byte comparison between old and new output |

## Benefits

1. **New credential type = new JSON file** — no Java code changes, no recompilation
2. **Metadata auto-generated** from credential profiles — always consistent
3. **SD-JWT support built-in** — profile declares which claims are selectively disclosable
4. **Multi-format per type** — same credential offered as `jwt_vc_json` and `dc+sd-jwt`
5. **Validation from schema** — can validate incoming credential data against profile claims
