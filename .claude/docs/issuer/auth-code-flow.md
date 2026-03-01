# Plan: Authorization Code Flow + Issuer-Initiated

## Overview

Implement the OID4VCI 1.0 Authorization Code grant alongside the existing pre-authorized_code grant. This includes PAR (Pushed Authorization Requests), PKCE S256, DPoP, and Issuer-Initiated issuance with `issuer_state`.

## Reference Flow (from fikua-lab)

### Issuer-Initiated Authorization Code Flow (18 steps)

```
1.  [User]    → Issuer Portal: "Issue credential for subject X"
2.  [Portal]  → Cert.lab: Certificate-based identification
3.  [Cert]    → Portal: Callback with identity data
4.  [Portal]  → Issuer Backend: POST /issuance (creates IssuanceRecord + CredentialOffer)
5.  [Wallet]  → Issuer Backend: GET /credential-offer/{id} (fetches offer)
6.  [Wallet]  → Issuer Backend: GET /.well-known/openid-credential-issuer (metadata)
7.  [Wallet]  → Detects grant_type: authorization_code (from offer)
8.  [Wallet]  → Issuer Backend: POST /oid4vci/v1/par (Pushed Authorization Request)
                 Body: client_id, redirect_uri, response_type=code, scope,
                       code_challenge, code_challenge_method=S256, issuer_state
                 Headers: DPoP JWT, Client-Assertion (WIA)
                 Response: { request_uri, expires_in }
9.  [Wallet]  → Issuer Backend: GET /oid4vci/v1/authorize?request_uri=...&client_id=...
                 Issuer resolves PAR data, generates auth code
                 Response: Redirect to redirect_uri with code + state + iss
10. [Wallet]  → Issuer Backend: POST /oauth/token
                 Body: grant_type=authorization_code, code, redirect_uri, code_verifier
                 Headers: DPoP JWT, Client-Assertion (WIA)
                 Response: { access_token (DPoP-bound), token_type: "DPoP", expires_in }
11. [Wallet]  → Issuer Backend: POST /oid4vci/v1/nonce
                 Body: (empty)
                 Response: { c_nonce, c_nonce_expires_in }
12. [Wallet]  → Issuer Backend: POST /oid4vci/v1/credential
                 Authorization: DPoP <access_token>
                 Body: { credential_configuration_id, proof: { jwt: "..." } }
                 Response: { credentials: [{ credential: "..." }] }
13. [Wallet]  → Issuer Backend: POST /oid4vci/v1/notification
```

## New Endpoints Required

### 1. PAR Endpoint

```
POST /oid4vci/v1/par
Content-Type: application/x-www-form-urlencoded

Parameters:
  client_id          = x509_hash:<thumbprint>    (or DID, depending on profile)
  redirect_uri       = https://wallet.example.com/callback
  response_type      = code
  scope              = eu.europa.ec.eudi.lear-employee_dc+sd-jwt
  code_challenge     = <base64url(SHA256(code_verifier))>
  code_challenge_method = S256
  issuer_state       = <from credential offer>   (optional, for issuer-initiated)
  state              = <wallet-generated state>

Headers:
  DPoP: <dpop_jwt>                               (HAIP only)
  Client-Assertion: <wia_jwt>                     (HAIP only)
  Client-Assertion-Type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer

Response (201 Created):
{
  "request_uri": "urn:ietf:params:oauth:request_uri:<uuid>",
  "expires_in": 60
}
```

### 2. Authorization Endpoint

```
GET /oid4vci/v1/authorize
  ?request_uri=urn:ietf:params:oauth:request_uri:<uuid>
  &client_id=x509_hash:<thumbprint>

Processing:
  1. Resolve request_uri from PAR store
  2. Validate client_id matches PAR
  3. If issuer_state present → lookup IssuanceRecord (issuer-initiated)
  4. If issuer_state absent → wallet-initiated (redirect to identification portal)
  5. Generate authorization_code (random, one-time-use, bound to PKCE + DPoP)
  6. Store: code → { client_id, redirect_uri, code_challenge, scope, issuer_state, dpop_jkt }

Response: 302 Redirect
  Location: <redirect_uri>?code=<auth_code>&state=<wallet_state>&iss=<issuer_url>
```

### 3. Nonce Endpoint

```
POST /oid4vci/v1/nonce
Content-Length: 0

Response (200 OK):
{
  "c_nonce": "<random-nonce>",
  "c_nonce_expires_in": 300
}
Cache-Control: no-store
```

### 4. Token Endpoint (extended)

Current `POST /oauth/token` only handles `pre-authorized_code` and `refresh_token`.

**Add `authorization_code` support**:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

Parameters:
  grant_type     = authorization_code
  code           = <from authorize redirect>
  redirect_uri   = <must match PAR>
  code_verifier  = <PKCE plain text, verified against code_challenge>

Headers:
  DPoP: <dpop_jwt>                               (HAIP only)

Processing:
  1. Lookup code → stored PAR data
  2. Validate redirect_uri matches
  3. PKCE: SHA256(code_verifier) == code_challenge
  4. DPoP: validate DPoP JWT, bind access_token to DPoP thumbprint
  5. Invalidate code (one-time use)
  6. Generate access_token (DPoP-bound if DPoP present, Bearer otherwise)

Response (200 OK):
{
  "access_token": "<jwt>",
  "token_type": "DPoP",           // or "Bearer" for plain profile
  "expires_in": 3600
}
Cache-Control: no-store
```

## New Java Components

### Models

```java
// PAR Request
public record PushedAuthorizationRequest(
    @BindParam("client_id") String clientId,
    @BindParam("redirect_uri") String redirectUri,
    @BindParam("response_type") String responseType,
    @BindParam("scope") String scope,
    @BindParam("code_challenge") String codeChallenge,
    @BindParam("code_challenge_method") String codeChallengeMethod,
    @BindParam("issuer_state") String issuerState,
    @BindParam("state") String state
) {}

// PAR Response
public record PushedAuthorizationResponse(
    @JsonProperty("request_uri") String requestUri,
    @JsonProperty("expires_in") int expiresIn
) {}

// Extended TokenRequest (add auth code fields)
public record TokenRequest(
    @BindParam("grant_type") String grantType,
    @BindParam("pre-authorized_code") String preAuthorizedCode,
    @BindParam("tx_code") String txCode,
    @BindParam("refresh_token") String refreshToken,
    // NEW fields for authorization_code:
    @BindParam("code") String code,
    @BindParam("redirect_uri") String redirectUri,
    @BindParam("code_verifier") String codeVerifier
) {}

// Authorization Code stored data
public record AuthorizationCodeData(
    String clientId,
    String redirectUri,
    String codeChallenge,
    String codeChallengeMethod,
    String scope,
    String issuerState,
    String dpopJkt,              // DPoP thumbprint (if DPoP used)
    String state,
    Instant createdAt,
    Instant expiresAt
) {}

// Nonce Response
public record NonceResponse(
    @JsonProperty("c_nonce") String cNonce,
    @JsonProperty("c_nonce_expires_in") int cNonceExpiresIn
) {}
```

### Stores (in-memory with TTL)

```java
// PAR Store — stores pushed authorization requests
@Component
public class ParStore {
    // Guava Cache with TTL (same pattern as CredentialOfferCacheRepository)
    private final Cache<String, AuthorizationRequestData> store;

    public String store(AuthorizationRequestData data) { ... }     // returns request_uri
    public AuthorizationRequestData resolve(String requestUri) { ... }  // one-time retrieval
}

// Authorization Code Store
@Component
public class AuthorizationCodeStore {
    private final Cache<String, AuthorizationCodeData> store;

    public String store(AuthorizationCodeData data) { ... }    // returns auth code
    public AuthorizationCodeData consume(String code) { ... }  // one-time retrieval
}

// Nonce Store
@Component
public class NonceStore {
    private final Cache<String, Instant> store;

    public String generate() { ... }                    // returns new nonce
    public boolean validate(String nonce) { ... }       // one-time validation
}
```

### Controllers

```java
// PAR Controller
@RestController
@RequestMapping("/oid4vci/v1/par")
public class ParController {
    @PostMapping(consumes = APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<PushedAuthorizationResponse> pushAuthorizationRequest(
        PushedAuthorizationRequest request,
        @RequestHeader(value = "DPoP", required = false) String dpopJwt
    ) { ... }
}

// Authorization Controller
@RestController
@RequestMapping("/oid4vci/v1/authorize")
public class AuthorizeController {
    @GetMapping
    public Mono<Void> authorize(
        @RequestParam("request_uri") String requestUri,
        @RequestParam("client_id") String clientId,
        ServerHttpResponse response  // for redirect
    ) { ... }
}

// Nonce Controller
@RestController
@RequestMapping("/oid4vci/v1/nonce")
public class NonceController {
    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<NonceResponse> getNonce() { ... }
}
```

### Services

```java
// PAR Service
public interface ParService {
    Mono<PushedAuthorizationResponse> processPar(PushedAuthorizationRequest request, String dpopJwt);
}

// Authorization Service
public interface AuthorizationService {
    Mono<URI> authorize(String requestUri, String clientId);
}

// Token Service extension
// Modify TokenServiceImpl to route by grant_type:
//   "urn:ietf:params:oauth:grant-type:pre-authorized_code" → existing flow
//   "authorization_code" → new flow (PKCE + optional DPoP)
//   "refresh_token" → existing flow
```

### PKCE Verification

```java
public class PkceVerifier {
    /**
     * Verifies PKCE S256: SHA256(code_verifier) == code_challenge
     */
    public static boolean verifyS256(String codeVerifier, String codeChallenge) {
        byte[] hash = MessageDigest.getInstance("SHA-256")
            .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        return MessageDigest.isEqual(
            computed.getBytes(StandardCharsets.US_ASCII),
            codeChallenge.getBytes(StandardCharsets.US_ASCII)
        );
    }
}
```

## DPoP Support (HAIP Profile)

### DPoP JWT Validation

```java
@Component
public class DpopValidator {
    /**
     * Validates a DPoP proof JWT per RFC 9449.
     */
    public Mono<String> validate(String dpopJwt, String httpMethod, String httpUri) {
        // 1. Parse DPoP JWT
        // 2. Verify signature (self-signed, using jwk in header)
        // 3. Validate claims: htm == httpMethod, htu == httpUri, iat recent, jti unique
        // 4. Return JWK thumbprint (for binding to access_token)
    }

    /**
     * Validates that an access token is bound to the DPoP key.
     */
    public Mono<Void> validateBinding(String accessToken, String dpopJwt) {
        // Verify access_token.cnf.jkt == SHA256(dpop_jwk)
    }
}
```

### DPoP JWT Structure

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
{
  "jti": "<unique-id>",
  "htm": "POST",
  "htu": "https://issuer.example.com/oauth/token",
  "iat": 1709000000
}
```

## Client Attestation / WIA (HAIP Profile)

### Wallet Instance Attestation Validation

```java
@Component
public class ClientAttestationValidator {
    /**
     * Validates client assertion JWT (WIA + PoP).
     * Per HAIP 1.0: client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
     */
    public Mono<Void> validate(String clientAssertionJwt, String clientId) {
        // 1. Parse outer JWT (WIA PoP)
        // 2. Extract inner WIA JWT from cnf claim
        // 3. Verify WIA signature (against trusted WIA issuer)
        // 4. Verify PoP binds to WIA
        // 5. Validate client_id matches WIA subject
    }
}
```

## Credential Offer Extension

### Current Offer (pre-authorized_code only)

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["eu.europa.ec.eudi.lear-employee_jwt_vc_json"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "<code>",
      "tx_code": { "input_mode": "numeric", "length": 4 }
    }
  }
}
```

### Extended Offer (authorization_code for issuer-initiated)

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["eu.europa.ec.eudi.lear-employee_dc+sd-jwt"],
  "grants": {
    "authorization_code": {
      "issuer_state": "<state-linking-to-issuance-record>"
    }
  }
}
```

### Dual Grant Offer (both options)

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["eu.europa.ec.eudi.lear-employee_dc+sd-jwt"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "<code>",
      "tx_code": { "input_mode": "numeric", "length": 4 }
    },
    "authorization_code": {
      "issuer_state": "<state>"
    }
  }
}
```

## Updated Authorization Server Metadata

```json
{
  "issuer": "https://issuer.example.com",
  "token_endpoint": "https://issuer.example.com/oauth/token",
  "authorization_endpoint": "https://issuer.example.com/oid4vci/v1/authorize",
  "pushed_authorization_request_endpoint": "https://issuer.example.com/oid4vci/v1/par",
  "jwks_uri": "https://issuer.example.com/oid4vci/v1/jwks",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "authorization_code"
  ],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"],
  "dpop_signing_alg_values_supported": ["ES256"],
  "pre-authorized_grant_anonymous_access_supported": true,
  "authorization_response_iss_parameter_supported": true,
  "require_pushed_authorization_requests": true
}
```

## Modified Files

| File | Change |
|------|--------|
| `TokenRequest.java` | Add `code`, `redirectUri`, `codeVerifier` fields |
| `TokenServiceImpl.java` | Add `authorization_code` routing in `validateGrantType()` and `validateByGrantType()` |
| `AuthorizationServerMetadata.java` | Add `authorization_endpoint`, `par_endpoint`, `dpop_signing_alg`, `code_challenge_methods` |
| `AuthorizationServerMetadataServiceImpl.java` | Generate extended metadata |
| `Constants.java` | Add `AUTHORIZATION_CODE_GRANT_TYPE`, endpoint paths |
| `EndpointsConstants.java` | Add PAR, authorize, nonce paths |
| `SecurityConfig.java` | Add new endpoints to filter chains |
| `CredentialOfferServiceImpl.java` | Support `authorization_code` grant in offer |
| `application.yml` | New config for PAR TTL, nonce TTL, auth code TTL |

## New Files

| File | Purpose |
|------|---------|
| `ParController.java` | PAR endpoint |
| `AuthorizeController.java` | Authorization endpoint |
| `NonceController.java` | Nonce endpoint |
| `ParService.java` + `Impl` | PAR processing logic |
| `AuthorizationService.java` + `Impl` | Auth code generation |
| `NonceService.java` + `Impl` | Nonce management |
| `PushedAuthorizationRequest.java` | PAR request model |
| `PushedAuthorizationResponse.java` | PAR response model |
| `AuthorizationCodeData.java` | Stored auth code data |
| `NonceResponse.java` | Nonce response model |
| `ParStore.java` | In-memory PAR store (Guava cache) |
| `AuthorizationCodeStore.java` | In-memory code store |
| `NonceStore.java` | In-memory nonce store |
| `PkceVerifier.java` | PKCE S256 verification |
| `DpopValidator.java` | DPoP JWT validation (HAIP) |
| `ClientAttestationValidator.java` | WIA validation (HAIP) |

## Implementation Order

### Phase 1: Core Authorization Code Flow (Plain Profile)
1. PAR endpoint (without DPoP/WIA)
2. Authorization endpoint
3. Nonce endpoint
4. Token endpoint extension (authorization_code grant + PKCE)
5. Credential Offer extension (authorization_code grant + issuer_state)
6. Authorization Server Metadata update

### Phase 2: HAIP Security Layer
7. DPoP validation
8. DPoP binding in token endpoint
9. Client Attestation (WIA) validation
10. Token type: `DPoP` instead of `Bearer`

### Phase 3: Issuer-Initiated + Wallet-Initiated
11. Issuer-initiated with issuer_state (link PAR to IssuanceRecord)
12. Wallet-initiated without issuer_state (redirect to identification portal)

## Retrocompatibility

| Concern | Strategy |
|---------|----------|
| Pre-authorized_code flow | Untouched. `TokenServiceImpl` routes by `grant_type` |
| Pre-auth + tx_code (OTP) | Untouched. PIN validation in existing path |
| Existing Credential Offer | Still works with `pre-authorized_code` grant only |
| Token endpoint path (`/oauth/token`) | Same path, additional grant_type accepted |
| Bearer tokens | Still accepted (DPoP optional unless HAIP profile enforced) |
| `proof` (singular) in credential request | Still supported alongside `proofs` (plural) |
