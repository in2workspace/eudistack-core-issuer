# Plan: SD-JWT Implementation

## Background

### What is SD-JWT?

SD-JWT (Selective Disclosure JWT) allows a holder to selectively disclose claims to a verifier. The issuer creates a JWT with hashed claim references, and provides the actual claim values as separate disclosures.

### Format: `dc+sd-jwt`

Per SD-JWT VC draft-14 (the format used in EUDI/HAIP), the media type is `dc+sd-jwt` (changed from `vc+sd-jwt` to avoid conflict with W3C's registered `vc` media type).

### Structure

```
<issuer-signed-jwt>~<disclosure1>~<disclosure2>~...~
```

Where:
- **Issuer-signed JWT**: Standard JWT with `typ: dc+sd-jwt`, containing `_sd` array and `_sd_alg`
- **Disclosures**: Base64url-encoded JSON arrays: `[salt, claim_name, claim_value]`
- **Separator**: `~` (tilde)

## Current State

- The issuer only supports `jwt_vc_json` (W3C VCDM v2.0)
- `nimbus-jose-jwt:9.40` does NOT include SD-JWT natively
- The `StatusListProvider` SPI mentions `sd-jwt` in a type reference but no implementation exists
- `cnf` (confirmation/holder binding) already partially implemented in `LEARCredentialEmployeeFactory`

## Implementation Design

### SD-JWT Building Pipeline

```
CredentialProfile (JSON Schema)
    │
    ├─ claims[].selective_disclosure == true → these become _sd disclosures
    ├─ claims[].selective_disclosure == false → these stay as plain claims
    │
    ▼
SdJwtBuilder
    │
    ├─ 1. Generate salt per SD claim (SecureRandom, 128-bit, base64url)
    ├─ 2. Create disclosure: base64url([salt, claim_name, claim_value])
    ├─ 3. Hash disclosure: SHA-256(disclosure) → base64url
    ├─ 4. Build payload with:
    │      - _sd: [hash1, hash2, ...] (hashed disclosures)
    │      - _sd_alg: "sha-256"
    │      - Non-SD claims as plain values
    │      - Standard claims: iss, iat, exp, vct, cnf
    ├─ 5. Sign JWT with SigningProvider (same SPI as jwt_vc_json)
    │
    ▼
Output: <signed-jwt>~<disclosure1>~<disclosure2>~...~
```

### New Components

#### SdJwtBuilder

```java
@Component
@RequiredArgsConstructor
public class SdJwtBuilder {

    private static final String SD_ALG = "sha-256";
    private static final int SALT_BYTES = 16;
    private final SecureRandom secureRandom = new SecureRandom();
    private final ObjectMapper objectMapper;

    /**
     * Builds an SD-JWT credential from a profile and subject data.
     *
     * @param profile     Credential profile (defines which claims are SD)
     * @param subjectData Raw claim values from the issuance request
     * @param issuerUrl   Issuer URL (iss claim)
     * @param cnf         Confirmation key (holder binding)
     * @return SdJwtComponents containing the unsigned payload + disclosures
     */
    public SdJwtComponents build(
            CredentialProfile profile,
            JsonNode subjectData,
            String issuerUrl,
            Map<String, Object> cnf) {

        List<Disclosure> disclosures = new ArrayList<>();
        ObjectNode payload = objectMapper.createObjectNode();
        ArrayNode sdArray = objectMapper.createArrayNode();

        // Standard claims
        payload.put("iss", issuerUrl);
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", Instant.now().plus(profile.validityDays(), ChronoUnit.DAYS).getEpochSecond());
        payload.put("vct", profile.sdJwt().vct());

        // CNF (holder binding)
        payload.set("cnf", objectMapper.valueToTree(cnf));

        // Process claims
        for (CredentialProfile.ClaimDefinition claim : profile.claims()) {
            JsonNode value = resolveClaimValue(subjectData, claim.sourceField());
            if (value == null && claim.mandatory()) {
                throw new IllegalArgumentException("Missing mandatory claim: " + claim.sourceField());
            }
            if (value == null) continue;

            if (claim.selectiveDisclosure()) {
                // Create disclosure and add hash to _sd
                Disclosure disclosure = createDisclosure(claim.path(), value);
                disclosures.add(disclosure);
                sdArray.add(disclosure.hash());
            } else {
                // Add as plain claim
                setNestedValue(payload, claim.path(), value);
            }
        }

        payload.set("_sd", sdArray);
        payload.put("_sd_alg", SD_ALG);

        return new SdJwtComponents(payload, disclosures);
    }

    private Disclosure createDisclosure(List<String> path, JsonNode value) {
        byte[] saltBytes = new byte[SALT_BYTES];
        secureRandom.nextBytes(saltBytes);
        String salt = Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);

        // Claim name is the leaf of the path
        String claimName = path.get(path.size() - 1);

        // Disclosure: base64url(JSON([salt, claim_name, claim_value]))
        String disclosureJson = objectMapper.writeValueAsString(
            List.of(salt, claimName, objectMapper.treeToValue(value, Object.class))
        );
        String encoded = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(disclosureJson.getBytes(StandardCharsets.UTF_8));

        // Hash: base64url(SHA-256(encoded))
        byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(
            encoded.getBytes(StandardCharsets.UTF_8)
        );
        String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);

        return new Disclosure(encoded, hash, claimName);
    }
}
```

#### SdJwtComponents (value object)

```java
public record SdJwtComponents(
    ObjectNode payload,           // The JWT payload (unsigned)
    List<Disclosure> disclosures  // The disclosure strings
) {
    /**
     * Combines the signed JWT with disclosures in SD-JWT format.
     */
    public String serialize(String signedJwt) {
        StringBuilder sb = new StringBuilder(signedJwt);
        for (Disclosure d : disclosures) {
            sb.append('~').append(d.encoded());
        }
        sb.append('~');  // Trailing tilde
        return sb.toString();
    }
}

public record Disclosure(
    String encoded,   // base64url([salt, name, value])
    String hash,      // base64url(SHA-256(encoded))
    String claimName  // Human-readable claim name
) {}
```

#### Integration with GenericCredentialBuilder

```java
// In GenericCredentialBuilder.buildSdJwt():
private Mono<String> buildSdJwt(
        CredentialProfile profile,
        JsonNode subjectData,
        String issuerUrl,
        Map<String, Object> cnf) {

    SdJwtComponents components = sdJwtBuilder.build(profile, subjectData, issuerUrl, cnf);

    // Build JWT header
    Map<String, Object> header = Map.of(
        "typ", "dc+sd-jwt",
        "alg", "ES256"
        // kid added by SigningProvider
    );

    String payloadJson = objectMapper.writeValueAsString(components.payload());

    // Sign using existing SigningProvider SPI (same as jwt_vc_json)
    return signingProvider.sign(payloadJson, header)
        .map(signedJwt -> components.serialize(signedJwt));
}
```

### JWT Header for SD-JWT

```json
{
  "typ": "dc+sd-jwt",
  "alg": "ES256",
  "kid": "issuer-key-id"
}
```

### JWT Payload Example (EUDI PID as SD-JWT)

```json
{
  "iss": "https://issuer.eudistack.eu",
  "iat": 1709000000,
  "exp": 1710609600,
  "vct": "urn:eu.europa.ec.eudi:lear-employee:1",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  },
  "credentialSubject": {
    "mandate": {
      "mandator": {
        "organizationIdentifier": "VATES-B60645900",
        "organization": "IN2, Ingeniería de la Información, S.L.",
        "commonName": "IN2",
        "country": "ES"
      },
      "power": [
        {
          "type": "Domain",
          "domain": "DOME",
          "function": "Onboarding",
          "action": "Execute"
        }
      ]
    }
  },
  "_sd": [
    "abc123...",
    "def456...",
    "ghi789..."
  ],
  "_sd_alg": "sha-256"
}
```

Disclosures (for firstName, lastName, email):
```
~WyJzYWx0MSIsImZpcnN0TmFtZSIsIk9yaW9sIl0~
~WyJzYWx0MiIsImxhc3ROYW1lIiwiQ2FuYWTDqXMiXQ~
~WyJzYWx0MyIsImVtYWlsIiwib3Jpb2wuY2FuYWRlc0BpbjIuZXMiXQ~
```

## Credential Endpoint Changes

### Format Negotiation

The credential endpoint must support both formats:

```java
// In CredentialIssuanceWorkflowImpl:
public Mono<CredentialResponse> generateCredential(CredentialRequest request, ...) {
    String configId = request.credentialConfigurationId();
    CredentialProfile profile = registry.getProfile(configId);

    return switch (profile.format()) {
        case "jwt_vc_json" -> buildAndSignJwtVcJson(profile, ...);
        case "dc+sd-jwt"   -> buildAndSignSdJwt(profile, ...);
        default -> Mono.error(new UnsupportedFormatException(profile.format()));
    };
}
```

### Metadata Declaration

Each credential type gets two `credential_configuration_ids`:

```json
{
  "credential_configurations_supported": {
    "eu.europa.ec.eudi.lear-employee_jwt_vc_json": {
      "format": "jwt_vc_json",
      "credential_definition": {
        "type": ["VerifiableCredential", "LEARCredentialEmployee"]
      }
    },
    "eu.europa.ec.eudi.lear-employee_dc+sd-jwt": {
      "format": "dc+sd-jwt",
      "vct": "urn:eu.europa.ec.eudi:lear-employee:1",
      "credential_metadata": {
        "claims": [
          { "path": ["credentialSubject", "mandate", "mandatee", "firstName"], ... },
          { "path": ["credentialSubject", "mandate", "mandatee", "lastName"], ... }
        ]
      }
    }
  }
}
```

## Dependencies

- **No new library needed**: SD-JWT is built on standard JWT + SHA-256 hashing + Base64url encoding
- **Existing `nimbus-jose-jwt`**: Used for JWT signing (same as today)
- **Existing `SigningProvider` SPI**: Signs the SD-JWT exactly like it signs jwt_vc_json
- **Requires**: Credential JSON Schema (Block A) to know which claims are SD

## Implementation Order

1. **SdJwtBuilder** + `SdJwtComponents` + `Disclosure` — pure logic, no dependencies on existing code
2. **Unit tests** for SD-JWT building (known test vectors from SD-JWT spec)
3. **Integration with GenericCredentialBuilder** — `buildSdJwt()` method
4. **Credential endpoint format negotiation** — route by `credential_configuration_id`
5. **Metadata update** — declare `dc+sd-jwt` configurations
6. **End-to-end test** — issue SD-JWT, verify disclosures

## Retrocompatibility

| Concern | Strategy |
|---------|----------|
| Existing `jwt_vc_json` credentials | Unchanged — SD-JWT is a new format, not a replacement |
| Wallets that only support `jwt_vc_json` | Will request the `_jwt_vc_json` configuration ID |
| Wallets that support `dc+sd-jwt` | Will request the `_dc+sd-jwt` configuration ID |
| Credential Offer | Can offer both formats in `credential_configuration_ids` array |
| SigningProvider SPI | No changes — signs JWT payload bytes regardless of `typ` header |
| Database | `credential_format` column already exists — will store `dc+sd-jwt` |
