# Current Architecture Audit

## Project Structure

```
src/main/java/es/in2/issuer/backend/
├── backoffice/                          # Admin/management UI backend
│   ├── application/
│   │   └── workflow/
│   │       ├── policies/                # BackofficePdpService (sign/remind authorization)
│   │       └── impl/                    # ActivationCodeWorkflow, IssuanceWorkflow
│   ├── domain/
│   │   ├── model/entities/              # CloudProvider, SignatureConfiguration, etc.
│   │   ├── service/                     # CertificateService, CredentialOfferService, etc.
│   │   └── util/factory/               # SignatureConfigAuditFactory
│   └── infrastructure/
│       ├── config/
│       │   ├── adapter/                 # Azure/Yaml config adapters
│       │   └── security/               # SecurityConfig, JwtDecoderConfig, CORS, R2DBC auditing
│       └── controller/                  # IssuanceController, SignatureConfigurationController
│
├── oidc4vci/                            # OID4VCI protocol implementation
│   ├── application/
│   │   └── workflow/                    # CredentialOfferWorkflow, PreAuthorizedCodeWorkflow
│   ├── domain/
│   │   ├── model/                       # CredentialIssuerMetadata, AuthorizationServerMetadata,
│   │   │                                  TokenRequest, TokenResponse
│   │   └── service/                     # TokenService, CredentialIssuerMetadataService
│   └── infrastructure/
│       └── controller/                  # TokenController, CredentialController, MetadataControllers,
│                                          CredentialOfferController, DeferredCredentialController,
│                                          NotificationController
│
├── shared/                              # Cross-cutting concerns
│   ├── application/
│   │   └── workflow/                    # CredentialIssuanceWorkflow, CredentialSignerWorkflow,
│   │                                      DeferredCredentialWorkflow
│   ├── domain/
│   │   ├── model/
│   │   │   ├── dto/                     # CredentialRequest/Response, PreSubmittedCredentialDataRequest
│   │   │   ├── dto/credential/          # Issuer, CredentialStatus, LEARCredential hierarchy
│   │   │   ├── entities/                # CredentialProcedure, DeferredCredentialMetadata
│   │   │   └── enums/                   # CredentialStatusEnum, CredentialType, SignatureMode
│   │   ├── exception/                   # 61 domain-specific exceptions
│   │   ├── service/                     # JWTService, AccessTokenService, VerifierService,
│   │   │                                  ProofValidationService, M2MTokenService, etc.
│   │   └── util/
│   │       ├── factory/                 # CredentialFactory, LEARCredentialEmployeeFactory,
│   │       │                              LEARCredentialMachineFactory, LabelCredentialFactory,
│   │       │                              IssuerFactory
│   │       ├── Constants.java           # GRANT_TYPE, credential types, contexts, expiration times
│   │       └── EndpointsConstants.java  # All endpoint paths
│   └── infrastructure/
│       ├── config/                      # AppConfig, AuthServerConfig, WebClientConfig
│       │   ├── properties/              # AppProperties, AuthServerProperties, CorsProperties
│       │   └── security/service/        # VerifiableCredentialPolicyAuthorizationService
│       ├── controller/                  # GlobalExceptionHandler, ErrorResponseFactory
│       ├── crypto/                      # CryptoComponent (EC P-256 key management)
│       └── repository/                  # CredentialProcedureRepository, DeferredCredentialMetadataRepository,
│                                          CredentialOfferCacheRepository (Guava in-memory)
│
├── signing/                             # Credential signing (pluggable SPI)
│   ├── domain/
│   │   ├── model/                       # SigningRequest, SigningResult
│   │   ├── service/                     # QtspIssuerService, RemoteSignatureService,
│   │   │                                  JadesHeaderBuilderService
│   │   └── spi/                         # SigningProvider interface
│   └── infrastructure/
│       ├── adapter/                     # InMemorySigningProvider, CscSignHashSigningProvider,
│       │                                  CscSignDocSigningProvider, DelegatingSigningProvider
│       ├── config/                      # DefaultSignerConfig, SigningRuntimeProperties
│       └── qtsp/                        # QtspAuthClient (CSC OAuth + TOTP)
│
└── statuslist/                          # Credential revocation
    ├── application/                     # RevocationWorkflow, StatusListWorkflow
    │   └── policies/                    # StatusListPdpService
    ├── domain/
    │   ├── factory/                     # BitstringStatusListCredentialFactory
    │   ├── model/                       # StatusList, StatusListIndex entities
    │   └── service/                     # BitstringStatusListRevocationService
    └── infrastructure/
        ├── adapter/                     # BitstringStatusListProvider, StatusListSigner
        └── controller/                  # StatusListController
```

## Endpoints

### OID4VCI Protocol (publicFilterChain - Order 1)

| Method | Path | Controller | Auth |
|--------|------|-----------|------|
| GET | `/.well-known/openid-credential-issuer` | CredentialIssuerMetadataController | Public |
| GET | `/.well-known/openid-configuration` | AuthorizationServerMetadataController | Public |
| POST | `/oauth/token` | TokenController | Public |
| GET | `/oid4vci/v1/credential-offer/{id}` | CredentialOfferController | Public |
| POST | `/oid4vci/v1/credential` | CredentialController | Bearer (Verifier/Issuer token) |
| POST | `/oid4vci/v1/deferred-credential` | DeferredCredentialController | Bearer |
| POST | `/oid4vci/v1/notification` | NotificationController | Bearer |

### VCI Issuances (publicFilterChain - custom auth)

| Method | Path | Auth |
|--------|------|------|
| POST | `/vci/v1/issuances` | Bearer (Verifier token + optional X-ID-Token) |

### Backoffice (internalFilterChain - Order 2)

| Method | Path | Auth |
|--------|------|------|
| GET/POST/PUT/DELETE | `/backoffice/**` | Keycloak JWT |
| GET/POST | `/status-list/**` | GET: public, POST: Keycloak JWT |
| GET/PUT | `/signing/**` | Currently permitAll (signing config) |

### Health & Monitoring

| Method | Path | Auth |
|--------|------|------|
| GET | `/actuator/health` | Public |
| GET | `/actuator/prometheus` | Public |
| GET | `/v3/api-docs/**` | Public |

## Database Schema (10 Flyway Migrations)

### Core Tables

```sql
credential_procedure (
    procedure_id     UUID PRIMARY KEY,
    credential_format VARCHAR,
    credential_decoded TEXT,
    credential_encoded TEXT,
    credential_status  VARCHAR,    -- VALID, REVOKED, WITHDRAWN, etc.
    credential_type    VARCHAR,    -- LEAR_CREDENTIAL_EMPLOYEE, LEAR_CREDENTIAL_MACHINE, LABEL_CREDENTIAL
    organization_identifier VARCHAR,
    email              VARCHAR,
    operation_mode     VARCHAR,
    signature_mode     VARCHAR,
    cnf                TEXT,       -- Confirmation key (holder binding)
    created_at         TIMESTAMP,
    updated_at         TIMESTAMP,
    created_by         VARCHAR(320),  -- From JWT principal (email or sub)
    updated_by         VARCHAR(320)
)

deferred_credential_metadata (
    id                UUID PRIMARY KEY,
    procedure_id      FK → credential_procedure,
    transaction_id    VARCHAR,
    transaction_code  VARCHAR,       -- tx_code / PIN
    auth_server_nonce VARCHAR,
    vc                TEXT,
    vc_format         VARCHAR,
    operation_mode    VARCHAR,
    response_uri      VARCHAR
)

status_list (
    id                 BIGSERIAL PRIMARY KEY,
    purpose            TEXT,
    encoded_list       TEXT,          -- Bitstring
    signed_credential  TEXT,
    created_at, updated_at TIMESTAMP
)

status_list_index (
    id              BIGSERIAL PRIMARY KEY,
    status_list_id  FK → status_list,
    idx             INTEGER,
    procedure_id    FK → credential_procedure,
    UNIQUE(procedure_id),
    UNIQUE(status_list_id, idx)
)

signature_configuration (
    id                       UUID PRIMARY KEY,
    organization_identifier  VARCHAR,
    enable_remote_signature  BOOLEAN,
    signature_mode           VARCHAR,    -- LOCAL, SERVER, CLOUD
    cloud_provider_id        FK → cloud_provider,
    client_id, secret_relative_path, credential_id VARCHAR
)

cloud_provider (
    id           UUID PRIMARY KEY,
    provider     VARCHAR UNIQUE,
    url          TEXT,
    auth_method, auth_grant_type VARCHAR,
    requires_totp BOOLEAN
)

configuration (
    id                       UUID PRIMARY KEY,
    organization_identifier  VARCHAR,
    config_key               VARCHAR,
    config_value             VARCHAR,
    UNIQUE(organization_identifier, config_key)
)

signature_configuration_audit (
    id, signature_configuration_id, user_email,
    old_values, new_values TEXT,
    instant TIMESTAMPTZ,
    rationale, encrypted TEXT/BOOLEAN
)
```

## Key Dependencies

| Category | Library | Version | Purpose |
|----------|---------|---------|---------|
| Framework | spring-boot-starter-webflux | 3.5.10 | Reactive web |
| Framework | spring-boot-starter-data-r2dbc | 3.5.10 | Reactive persistence |
| Framework | spring-boot-starter-security | 3.5.10 | OAuth2 resource server |
| JWT | nimbus-jose-jwt | 9.40 | JWT handling |
| JWT | oauth2-oidc-sdk | 11.21.1 | OID4VCI support |
| JWT | jjwt-api/impl/jackson | 0.12.5 | JWT operations |
| Encoding | cbor (upokecenter) | 4.5.4 | CBOR encoding |
| Encoding | cose-java | 1.1.0 | COSE structure |
| DB | r2dbc-postgresql | - | PostgreSQL driver |
| DB | flyway-core | - | Migrations |
| Cache | guava | 33.2.1 | In-memory cache (credential offers) |
| Resilience | resilience4j | - | Circuit breaker |
| Cloud | spring-cloud-azure-starter-appconfiguration | - | Azure App Config |
| Cloud | spring-vault-core | 3.1.2 | HashiCorp Vault |
| Docs | springdoc-openapi-starter-webflux-ui | 2.5.0 | OpenAPI/Swagger |
| Monitoring | micrometer-tracing-bridge-brave | - | Distributed tracing |
| Monitoring | micrometer-registry-prometheus | - | Metrics |

## Credential Types (Hardcoded)

### LEARCredentialEmployee

- **Format**: `jwt_vc_json` (W3C VCDM v2.0)
- **Factory**: `LEARCredentialEmployeeFactory`
- **Record**: `LEARCredentialEmployee` implements `LEARCredential`
- **Structure**: `@context`, `id`, `type`, `description`, `credentialSubject.mandate.{mandatee, mandator, power[]}`, `issuer`, `validFrom`, `validUntil`, `credentialStatus`
- **Context URLs**: `https://www.w3.org/ns/credentials/v2` + `https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3`

### LEARCredentialMachine

- **Format**: `jwt_vc_json`
- **Factory**: `LEARCredentialMachineFactory`
- **Context**: `https://www.w3.org/ns/credentials/v2` + `https://credentials.eudistack.eu/.well-known/credentials/lear_credential_machine/w3c/v2`

### LabelCredential (gx:LabelCredential)

- **Format**: `jwt_vc_json`
- **Factory**: `LabelCredentialFactory`
- **Context**: `https://www.w3.org/ns/credentials/v2` + `https://w3id.org/gaia-x/development#`

## Authentication Architecture

### Two Security Filter Chains

**Chain 1 (Order 1) - Public/OID4VCI**:
- Paths: `/oid4vci/**`, `/oauth/**`, `/vci/**`, `/.well-known/**`
- Auth: `CustomAuthenticationManager` → routes by JWT `iss` claim
  - `iss == verifierUrl` → `verifierService.verifyToken()`
  - `iss == issuerBackendUrl` → local signature validation
  - Other → rejected
- Accepts: `Authorization: Bearer` + optional `X-ID-Token` header

**Chain 2 (Order 2) - Internal/Backoffice**:
- Paths: `/backoffice/**`, `/status-list/**`, `/signing/**`
- Auth: Spring OAuth2 Resource Server → `internalJwtDecoder` (Keycloak JWKS)
- JWT decoder: `NimbusReactiveJwtDecoder` with Keycloak RS256 JWKS endpoint

### Principal Resolution

`JWTService.resolvePrincipal(jwt)`:
1. Prefer `email` claim (mandatee email from LEAR Credential)
2. Fallback to `sub` claim
3. Used for R2DBC `@CreatedBy` / `@LastModifiedBy` auditing

## Policy Decision Points (3 separate services)

### VerifiableCredentialPolicyAuthorizationServiceImpl
- **Location**: `shared/infrastructure/config/security/service/impl/`
- **Guards**: VCI issuance (`/vci/v1/issuances`)
- **Logic**:
  - Extract `role` claim → must be `LEAR`
  - Extract `vc` claim → parse into LEARCredential
  - Route by schema:
    - LEARCredentialEmployee: signer policy (admin org + Onboarding/Execute) OR mandator policy (same org + ProductOffering only)
    - LEARCredentialMachine: signer policy OR mandator policy (same org + Onboarding only)
    - LabelCredential: LEARCredentialMachine in access token + ID token validation against Verifier + Certification/Attest power

### BackofficePdpServiceImpl
- **Location**: `backoffice/application/workflow/policies/impl/`
- **Guards**: sign credential, send reminder
- **Logic**: parse token → role == LEAR → extract orgId from vc → sys-admin bypass OR match org with credential

### StatusListPdpServiceImpl
- **Location**: `statuslist/application/workflow/policies/impl/`
- **Guards**: revoke credential
- **Logic**: validate status == VALID → parse token → role == LEAR → extract orgId → sys-admin bypass OR match org

## Known Pain Points

1. **Credential definitions hardcoded** in Factory classes with if/else dispatch in `CredentialFactory`
2. **3 PDP services with duplicated code** (token parsing, role check, org extraction, sys-admin check)
3. **Keycloak still required** for backoffice endpoints despite OID4VCI already decoupled
4. **Metadata uses draft format** (`credential_definition.type[]` instead of OID4VCI 1.0 Final `credential_metadata.claims[].path[]`)
5. **AuthorizationServerMetadata** incomplete (missing `authorization_endpoint`, `par_endpoint`, `dpop_signing_alg`)
6. **TokenRequest** only supports `pre-authorized_code` and `refresh_token` (no `authorization_code`)
7. **No SD-JWT** implementation (only `jwt_vc_json`)
8. **No DPoP, PAR, PKCE, WIA** support
9. **Nonce validation stubbed** (comment says "TODO: Check nonce when implemented")
10. **COSE signing incomplete** (only Base64 normalization, not real COSE_Sign1)
11. **IssuerApiClientTokenService** uses ROPC flow (deprecated in OAuth 2.1)
12. **LEARCredentialEmployeeFactory.mapStringToLEARCredentialEmployee** has if/else for 3 different context URLs
