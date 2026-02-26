# Plan: Eliminate Keycloak Dependency

## Current State

The system has **two security filter chains** in `SecurityConfig.java`:

### Chain 1 - Public/OID4VCI (Order 1) - Already Keycloak-free

```
Paths: /oid4vci/**, /oauth/**, /vci/**, /.well-known/**
Auth:  CustomAuthenticationManager
       ├── iss == verifierUrl      → verifierService.verifyToken()
       ├── iss == issuerBackendUrl → local signature validation (JWTService)
       └── other                   → REJECTED
```

### Chain 2 - Internal/Backoffice (Order 2) - Keycloak-dependent

```
Paths: /backoffice/**, /status-list/**, /signing/**
Auth:  Spring OAuth2 Resource Server
       └── internalJwtDecoder (NimbusReactiveJwtDecoder)
           └── Keycloak JWKS endpoint (RS256)
           └── Keycloak realm as issuer validator
```

## Target State

**Single authentication flow for all endpoints**: Portal Issuer → Verifier (OID4VP) → access_token → Issuer Backend.

```
Portal Issuer (Frontend)
    │
    ├─ Presents VP to Verifier via OID4VP
    │   └─ Verifier validates VP, issues access_token with:
    │       - iss: verifier URL
    │       - vc: embedded LEARCredential (Employee or Machine)
    │       - role: "LEAR"
    │       - email: mandatee email
    │       - sub: subject identifier
    │
    ├─ Calls Issuer Backend:
    │   Authorization: Bearer <verifier_access_token>
    │   X-ID-Token: <optional_id_token>
    │
    └─ Issuer Backend (ALL endpoints):
        └─ CustomAuthenticationManager
            ├─ Extracts iss from token
            ├─ iss == verifierUrl → verifierService.verifyToken() ✓
            ├─ iss == issuerBackendUrl → local validation ✓
            └─ Passes to PDP service for authorization
```

## Files to Modify

### DELETE

| File | Reason |
|------|--------|
| `backoffice/infrastructure/config/security/JwtDecoderConfig.java` | Keycloak JWKS decoder no longer needed |
| `shared/domain/service/impl/IssuerApiClientTokenServiceImpl.java` | Uses Keycloak ROPC flow (deprecated) |
| `shared/domain/service/IssuerApiClientTokenService.java` | Interface for above |

### MODIFY

| File | Change |
|------|--------|
| **`SecurityConfig.java`** | **Critical**: Merge both chains or make `internalFilterChain` use `customAuthenticationWebFilter` instead of `oauth2ResourceServer(jwt)`. Remove `internalJwtDecoder` dependency. Add `/backoffice/**`, `/status-list/**`, `/signing/**` to the `customAuthenticationWebFilter` matcher. |
| `AuthServerProperties.java` | Remove Keycloak-specific properties: `external-url`, `internal-url`, `realm`, `jwt-decoder-path`, `jwt-decoder-local-path`, `jwt-validator-path`, `nonce-validation-path`. Keep only what M2M needs (if anything). |
| `AuthServerConfig.java` | Remove `getJwtDecoder()`, `getJwtValidator()`. Simplify to only expose what remains. |
| `application.yml` | Remove `auth-server.provider`, `auth-server.external-url`, `auth-server.internal-url`, `auth-server.realm`, `auth-server.paths.jwt-decoder-path`, etc. |
| `CustomAuthenticationManager.java` | No changes needed — already works correctly. Just now handles ALL authenticated endpoints. |
| `DualTokenServerAuthenticationConverter.java` | No changes needed. |

### VERIFY (no changes expected, but test)

| File | Why test |
|------|----------|
| `R2dbcAuditingConfig.java` | Already resolves principal generically from `Authentication.getName()`. Should work as-is. |
| `BackofficePdpServiceImpl.java` | Already parses `vc` claim from JWT. Token format doesn't change. |
| `StatusListPdpServiceImpl.java` | Same — parses `vc` from JWT. |
| `VerifiableCredentialPolicyAuthorizationServiceImpl.java` | Already receives raw token string. No Keycloak dependency. |

## SecurityConfig.java: Proposed Change

### Option A: Merge into single filter chain (recommended)

Remove `internalFilterChain` entirely. Expand `publicFilterChain` to cover all paths:

```java
@Bean
@Order(1)
public SecurityWebFilterChain unifiedFilterChain(ServerHttpSecurity http, ...) {
    http
        .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
            // Public OID4VCI paths (existing)
            CORS_OID4VCI_PATH, VCI_PATH, WELL_KNOWN_PATH, OAUTH_PATH,
            // Backoffice paths (migrated from internalFilterChain)
            BACKOFFICE_PATH, STATUS_LIST_PATH, SIGNING_PROVIDERS_PATH,
            SIGNING_CONFIG_PATH, HEALTH_PATH, PROMETHEUS_PATH, SPRINGDOC_PATH
        ))
        .cors(cors -> cors.configurationSource(mergedCorsSource()))
        .authorizeExchange(exchange -> exchange
            // Public endpoints (no auth)
            .pathMatchers(HttpMethod.GET,
                CORS_CREDENTIAL_OFFER_PATH,
                CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH,
                AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH,
                HEALTH_PATH, PROMETHEUS_PATH, SPRINGDOC_PATH,
                STATUS_LIST_PATH, SIGNING_PROVIDERS_PATH,
                BACKOFFICE_STATUS_CREDENTIALS
            ).permitAll()
            .pathMatchers(HttpMethod.POST, OAUTH_TOKEN_PATH).permitAll()
            .pathMatchers(HttpMethod.PUT, SIGNING_CONFIG_PATH).permitAll()
            // Authenticated endpoints (all go through CustomAuthenticationManager)
            .anyExchange().authenticated()
        )
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .addFilterAt(customAuthenticationWebFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION)
        .exceptionHandling(e -> e
            .authenticationEntryPoint(entryPoint)
            .accessDeniedHandler(deniedH)
        );
    return http.build();
}
```

### Option B: Keep two chains but both use CustomAuthenticationManager

Modify `internalFilterChain` to replace `.oauth2ResourceServer(jwt)` with the same `customAuthenticationWebFilter`:

```java
@Bean
@Order(2)
public SecurityWebFilterChain internalFilterChain(ServerHttpSecurity http, ...) {
    // ... same path matchers ...
    // REMOVE:
    // .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtDecoder(internalJwtDecoder)...))
    // ADD:
    .addFilterAt(backofficeAuthenticationWebFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION)
    // ... rest same ...
}
```

**Recommendation**: Option A is cleaner. Two chains with the same auth mechanism is unnecessary.

## CORS Consolidation

Currently there are two CORS configs:
- `InternalCORSConfig` (backoffice origins)
- `PublicCORSConfig` (OID4VCI origins, wallet origins)

After merging, create a **single CORS config** that combines both origin lists and applies path-based rules:

```java
// Open: metadata, credential offer
/well-known/**, /oid4vci/v1/credential-offer/** → any HTTPS origin

// Restricted: wallet/verifier
/oid4vci/v1/credential, /oauth/token, etc. → external-allowed-origins

// Internal: backoffice
/backoffice/**, /signing/** → default-allowed-origins (frontend URL)
```

## Prerequisites

Before deploying this change:

1. **Portal Issuer must already authenticate via Verifier** (OID4VP flow → access_token from Verifier)
2. **Verifier must issue tokens with the same claims** the PDP services expect:
   - `vc` claim containing LEARCredential JSON
   - `role` claim (value: `"LEAR"`)
   - `email` claim (mandatee email) or `sub` claim
3. **Verify Verifier token has sufficient lifetime** for backoffice sessions

## Migration Strategy

### Phase 1: Parallel Support (safe)
- Add backoffice paths to `customAuthenticationWebFilter` matcher
- Keep `internalFilterChain` as fallback
- Test: send Verifier tokens to backoffice endpoints

### Phase 2: Remove Keycloak chain
- Remove `internalFilterChain`
- Delete `JwtDecoderConfig`
- Delete Keycloak properties
- Test: all backoffice endpoints work with Verifier tokens only

### Phase 3: Cleanup
- Delete `IssuerApiClientTokenService` (ROPC flow)
- Simplify `AuthServerConfig` and `AuthServerProperties`
- Remove unused config from `application.yml`

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Backoffice breaks if Verifier token format differs from Keycloak | Medium | High | Test token format before migration |
| R2DBC auditing fails to resolve principal | Low | Medium | Already generic — uses `Authentication.getName()` |
| M2M service calls break | Low | Medium | M2M already uses Verifier, not Keycloak |
| CORS misconfiguration blocks frontend | Medium | High | Test with actual Portal Issuer |
