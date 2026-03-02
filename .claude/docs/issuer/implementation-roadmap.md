# Implementation Roadmap

## Work Blocks

| Block | Name | Complexity | Estimated New Files | Estimated Modified Files |
|-------|------|-----------|--------------------|-----------------------|
| **F** | Eliminate Keycloak ✅ | Medium | 0 | ~8 (delete 3) |
| **G** | Restructure PDP Policies ✅ | Medium | ~8 | ~6 |
| **A** | JSON Schema Credentials ✅ | Medium-High | 6 new | 9 modified |
| **B** | SD-JWT Format | High | ~6-8 | ~5-8 |
| **C** | Authorization Code Flow + Issuer-Initiated | Very High | ~15-20 | ~10-12 |
| **D** | DPoP + PKCE + WIA | High | ~6-8 | ~5-6 |
| **E** | Metadata Update | Medium | ~2-3 | ~4-5 |

## Dependency Graph

```
F (Keycloak Removal)
│
├──► G (Policy Restructuring)
│
└──► C (Auth Code Flow)
     │
     └──► D (DPoP + PKCE + WIA)
          │
          └──► E (Metadata Update) ◄── A (JSON Schema Credentials)
                                       │
                                       └── B (SD-JWT)
```

**Independent tracks** that can be parallelized:

```
Track 1 (Infra/Security)          Track 2 (Credentials/Formats)
─────────────────────────         ──────────────────────────────
F: Eliminate Keycloak              A: JSON Schema Credentials
        ↓                                  ↓
G: Restructure Policies            B: SD-JWT Format
        ↓                                  ↓
C: Auth Code Flow                  (waits for C to complete)
        ↓                                  ↓
D: DPoP + PKCE + WIA              E: Metadata Update
```

## Recommended Execution Order

### Phase 1: Foundation (parallel tracks)

**Track 1: F → G** (Security cleanup)

1. **F - Eliminate Keycloak**
   - Prereq: Portal Issuer already authenticates via Verifier
   - Change: Unify SecurityConfig to single filter chain with `CustomAuthenticationManager`
   - Delete: `JwtDecoderConfig`, `IssuerApiClientTokenService`, Keycloak properties
   - Risk: Medium — authentication is critical, but `CustomAuthenticationManager` already proven
   - See: [keycloak-removal.md](keycloak-removal.md)

2. **G - Restructure PDP Policies**
   - Prereq: F completed (tokens now uniform)
   - Change: Create `PolicyContext`, `PolicyContextFactory`, composable rules
   - Refactor: 3 PDP services from ~600 lines total to ~100 lines
   - Risk: Low — pure refactoring, same inputs → same outputs
   - See: [policy-restructuring.md](policy-restructuring.md)

**Track 2: A → B** (Credential formats)

3. **A - JSON Schema Credentials** ✅ COMPLETED
   - Prereq: None
   - Change: Created `CredentialProfile`, `CredentialProfileRegistry`, `GenericCredentialBuilder`
   - Migrated: 3 credential types to JSON profile files (`src/main/resources/credentials/profiles/`)
   - Also: Updated `CredentialIssuerMetadata` to OID4VCI 1.0 Final format (was originally planned for Block E)
   - Old factories kept as fallback in `CredentialFactory` and `CredentialSignerWorkflowImpl`
   - All 881+ tests pass, including new `CredentialProfileRegistryTest` and `GenericCredentialBuilderTest`
   - See: [credential-json-schema.md](credential-json-schema.md)

4. **B - SD-JWT Format**
   - Prereq: A completed (needs profile's `selective_disclosure` flags)
   - Change: Create `SdJwtBuilder`, `SdJwtComponents`, `Disclosure`
   - Integrate: `GenericCredentialBuilder.buildSdJwt()` method
   - Risk: Low — additive format, doesn't touch existing `jwt_vc_json`
   - See: [sd-jwt-implementation.md](sd-jwt-implementation.md)

### Phase 2: Authorization Code Flow

5. **C - Auth Code Flow + Issuer-Initiated**
   - Prereq: F completed (clean auth architecture)
   - Change: New PAR, Authorize, Nonce endpoints + Token endpoint extension
   - Risk: Medium — token endpoint modification requires careful routing
   - See: [auth-code-flow.md](auth-code-flow.md)

6. **D - DPoP + PKCE + WIA**
   - Prereq: C completed (auth code flow must work first)
   - Change: Add `DpopValidator`, `ClientAttestationValidator`, PKCE verification
   - Risk: Medium — security-critical, needs thorough testing
   - See: [auth-code-flow.md](auth-code-flow.md) (Phase 2 section)

### Phase 3: Finalization

7. **E - Metadata Update** (partially done in Block A)
   - Prereq: A + C completed
   - Done: `CredentialIssuerMetadata` updated to OID4VCI 1.0 Final, auto-generated from `CredentialProfileRegistry`
   - Remaining: Update `AuthorizationServerMetadata` (depends on Block C auth code flow endpoints)
   - Risk: Low — additive fields only
   - See: [gap-analysis.md](gap-analysis.md) (Metadata section)

## Retrocompatibility Checklist

Each block MUST pass these checks before merging:

- [ ] All existing 161 test files pass without modification
- [ ] Pre-authorized_code flow works end-to-end (with and without tx_code)
- [ ] W3C VCDM v2.0 `jwt_vc_json` credentials are byte-identical
- [ ] Metadata endpoints return all existing fields
- [ ] Deferred credential flow works
- [ ] Status list revocation works
- [ ] Signing SPI (InMemory + CscSignHash) works for all formats
- [ ] Database: no destructive migrations, additive only

## Database Migrations Required

| Block | Migration | Description |
|-------|-----------|-------------|
| C | V11__Add_par_store.sql | Table for PAR request storage (or use in-memory cache) |
| C | V12__Add_auth_code_store.sql | Table for auth codes (or use in-memory cache) |
| C | V13__Add_nonce_store.sql | Table for nonces (or use in-memory cache) |

**Note**: PAR, auth codes, and nonces are short-lived (60s-300s TTL). In-memory Guava cache is acceptable for single-instance deployment. For multi-instance, use PostgreSQL or Redis.

## Configuration Changes

### New Properties (application.yml)

```yaml
oid4vci:
  par:
    ttl-seconds: 60              # PAR request_uri lifetime
  authorization-code:
    ttl-seconds: 300             # Auth code lifetime
  nonce:
    ttl-seconds: 300             # c_nonce lifetime
  dpop:
    enabled: false               # Enable DPoP validation (HAIP profile)
    max-age-seconds: 120         # DPoP JWT max age
  client-attestation:
    enabled: false               # Enable WIA validation (HAIP profile)
```

### Removed Properties (after Keycloak elimination)

```yaml
# DELETE:
auth-server:
  provider: keycloak
  external-url: ...
  internal-url: ...
  realm: ...
  paths:
    jwt-decoder-path: ...
    jwt-decoder-local-path: ...
    jwt-validator-path: ...
    nonce-validation-path: ...
  client:
    client-id: ...
    username: ...
    password: ...
```

## Risk Matrix

| Block | Technical Risk | Breaking Risk | Security Risk |
|-------|---------------|---------------|---------------|
| F (Keycloak) | Medium | Medium | **High** (auth change) |
| G (Policies) | Low | Low | Low (same behavior) |
| A (JSON Schema) | Low | Low | Low (same output) |
| B (SD-JWT) | Medium | **None** (additive) | Low |
| C (Auth Code) | High | Low (new endpoints) | **High** (new auth flow) |
| D (DPoP/WIA) | High | **None** (additive) | **High** (security-critical) |
| E (Metadata) | Low | Low (additive fields) | Low |

## Success Criteria

### OID4VCI 1.0 Compliance
- [ ] Pre-authorized_code flow (plain profile) ✓ (already done)
- [ ] Pre-authorized_code + tx_code ✓ (already done)
- [ ] Authorization code flow (plain profile)
- [ ] Authorization code flow (HAIP profile with DPoP + PKCE + WIA)
- [ ] Issuer-initiated with authorization_code
- [x] Credential Issuer Metadata (1.0 Final format) — done in Block A
- [ ] Authorization Server Metadata (complete)
- [ ] Nonce endpoint
- [ ] `dc+sd-jwt` format
- [ ] `jwt_vc_json` format (maintained)

### Code Quality
- [x] Credential types defined by JSON files, not Java code — done in Block A
- [ ] Single PDP framework with composable rules
- [ ] No Keycloak dependency
- [ ] All endpoints documented in OpenAPI
- [ ] Test coverage maintained (>1.5:1 ratio)
