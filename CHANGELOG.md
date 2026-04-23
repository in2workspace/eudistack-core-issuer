# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.4.3] - 2026-04-23

### Fixed

- **`TenantDomainWebFilter`**: strip known environment suffixes (`-stg`, `-dev`, `-pre`) from the tenant identifier before the `tenant_registry` lookup. Non-prod DNS follows the `{tenant}-{env}.eudistack.net` pattern (e.g. `sandbox-stg.eudistack.net`), so the filter previously returned `404 TENANT_NOT_FOUND` when resolving `sandbox-stg` against a registry that only contains `sandbox`. The strip runs after the `TENANT_NAME_PATTERN` validation and covers both the `X-Tenant-Id` header and the host-derived path. Tenant schemas remain environment-agnostic across local/stg/pre/pro.

## [3.4.2] - 2026-04-22

### Fixed

- **Issuer startup on STG**: disabled Spring Boot's auto-configured `flywayInitializer` (`spring.flyway.enabled: false`) in `application.yml`. The auto-config was attempting a JDBC connection without user/password (only `SPRING_FLYWAY_URL` is injected in ECS), causing `SCRAM-based authentication, but no password was provided` and aborting context startup. `TenantSchemaFlywayMigrator` continues to run migrations for `public` + all tenant schemas using R2DBC credentials.

## [3.4.1] - 2026-04-22

### Changed (EUDI-065 — `APP_MAIL_FROM` per-tenant)

- **`EmailServiceImpl`** now resolves the transactional email sender via `TenantConfigService.getStringOrThrow("issuer.mail_from")` inside each public method, so every tenant can send from its own address once SES has it verified. Public `EmailService` API unchanged.
- **`app.mail-from`** removed from `application.yml`; **`APP_MAIL_FROM`** removed from `docker/docker-compose.yml`.
- **Flyway V3 per-tenant migration** (`V3__Seed_mail_from_placeholder.sql`) seeds a `issuer.mail_from` placeholder so existing environments don't fail on `getStringOrThrow` before the real seed runs.
- **`EmailServiceImpl.sendTxCodeNotification`** now logs the original exception before mapping to `EmailCommunicationException` (the previous `onErrorMap` lambda swallowed the cause).

### Tests

- Updated `EmailServiceImplTest` to inject a mocked `TenantConfigService` returning the test mail_from.
- Sibling change in `eudistack-platform-dev`: `seed-tenants[.stg].sql` seeds `issuer.mail_from` for all 4 tenants (`noreply@mail-stg.eudistack.net`).

## [3.4.0] - 2026-04-22

### Changed (EUDI-025 US-09 — QTSP signing 100% per-tenant)

**BREAKING (internal contract):** all QTSP signing paths read configuration exclusively from `tenant_signing_config`; no global fallback. A tenant without a row in that table fails only its own signing operations, isolated from the rest.

- **`SigningRequest` extended** with `remoteSignature: RemoteSignatureDto`. `DelegatingSigningProvider` resolves the tenant's QTSP config via `TenantSigningConfigService.getRemoteSignature()` and injects it into the request before delegating to the concrete CSC provider.
- **`QtspAuthClient`, `QtspSignHashPort` + `QtspSignHashClient`, `QtspIssuerService` + impl, `RemoteSignatureServiceImpl`, `JwsSignHashService` + impl** now take `RemoteSignatureDto` (directly or via `SigningRequest`) instead of reading a global bean. `QtspIssuerService.getCredentialId()` removed — callers use `cfg.credentialId()` directly.
- **`IssuerFactory`** (StatusList) now resolves the tenant's QTSP config from `TenantSigningConfigService` and passes it to `qtspIssuerService.resolveRemoteDetailedIssuer(cfg)`. If the tenant has no signing config, fails fast with `SigningException`.
- **`DelegatingSigningProvider`** throws `SigningException` when `tenant_signing_config` is empty for the current tenant.
- **`TenantSigningConfigService`**: removed `getProvider()` and the global fallback in `getRemoteSignature()`. Returns `Mono.empty()` when the tenant has no row.

### Removed

- **`RuntimeSigningConfig`** bean + **`SigningRuntimeConfigProperties`** + **`RemoteSignatureProperties`** + **`SigningRuntimeConfigController`** + **`SigningConfigPushRequest`** DTO + test.
- **`PUT /internal/signing/config`** and **`GET /internal/signing/provider`** endpoints — per-tenant config is seeded via SQL or (future) a dedicated config management service.
- **`@ConditionalOnProperty(issuer.signing.runtime.enabled)`** from `SigningProviderConfig` — the signing module is always wired.
- **`signing.runtime.*`** and **`signing.remote-signature.*`** blocks from `application.yml`.
- **`SIGNING_RUNTIME_ENABLED`, `SIGNING_RUNTIME_CONTROLLER_ENABLED`, `SIGNING_DEFAULT_PROVIDER`, `SIGNING_REMOTE_*`** env vars from `docker/docker-compose.yml`.
- **`SIGNING_PROVIDERS_PATH`, `SIGNING_CONFIG_PATH`** constants from `EndpointsConstants` + their entries in `SecurityConfig`. Related tests removed from `SecurityConfigTest`.

### Changed (health indicator)

- **`SigningServiceHealthIndicator`** simplified — signing is per-tenant, so the global up/down no longer depends on a shared config. Reports `mode=per-tenant`.

### Tests

- Updated: `DelegatingSigningProviderTest`, `QtspAuthClientTest`, `QtspSignHashClientTest`, `QtspIssuerServiceImplTest`, `RemoteSignatureServiceImplTest`, `CscSignHashSigningProviderTest`, `CscSignDocSigningProviderTest`, `JwsSignHashServiceImplTest`, `SigningProviderConfigTest`, `IssuerFactoryTest`. All 765 tests pass.
- Sibling change in `eudistack-platform-dev`: `seed-tenants[.stg].sql` seeds `tenant_signing_config` for all 4 tenants with mock-qtsp (local and STG both have mock-qtsp reachable).

## [3.3.1] - 2026-04-22

### Removed (compose/env cleanup — no breaking at runtime)

- **Dead config keys** removed from `AppProperties`, `AppConfig`, `IssuerProperties`, `application.yml` and `docker/docker-compose.yml`:
  - `app.issuer-frontend-url` / `APP_ISSUER_FRONTEND_URL` — no runtime consumers (only referenced in `cors-origins.yaml` comments and tests).
  - `app.wallet-url` / `APP_WALLET_URL` / `getWalletFrontendUrl()` — replaced by `tenant_config.issuer.wallet_url` (read via `TenantConfigService.getStringOrThrow`).
  - `app.knowledge-base.*` / `APP_KNOWLEDGE_BASE_*` + record `AppProperties.KnowledgeBase` — never consumed by the backend (the MFE reads `theme.json#content.knowledgeBaseUrl` per tenant).
  - `APP_CONFIG_SOURCE` — never read (was declared only in docker-compose).
  - `ISSUER_IDENTITY_JWT_CREDENTIAL` — already documented as dead code.

### Changed (EUDI-065 Fase 8 — per-tenant wallet URL enforcement)

- **`CredentialOfferServiceImpl.buildCredentialOfferUri`** now resolves `issuer.wallet_url` per-tenant via `tenantConfigService.getStringOrThrow` (no global fallback). The method signature returns `Mono<String>` for the email channel — required to chain the async config lookup. Matches the pattern already applied to `admin_organization_id` in 3.3.0.

## [3.3.0] - 2026-04-21

### Added (EUDI-065 Fase 8 / EUDI-025 US-08)

- **`GET /api/v1/me`** (`MeController` + `MeResponse` DTO). Resuelve el rol del caller contra el tenant actual usando `AccessTokenService.getAuthorizationContext` y lo expone al frontend. Registrado en `SecurityConfig.unifiedFilterChain` como endpoint autenticado. Unit tests: `MeControllerTest` (happy path TenantAdmin en KPMG, SysAdmin read-only en platform).
- **`TenantConfigService.getStringOrThrow(key)`** + **`TenantConfigMissingException`** para claves requeridas por tenant. Si la clave no está seeded, falla solo el tenant afectado (los demás siguen operativos).
- **`TenantDomainWebFilter`** bypass para `/health` y `/prometheus` (evita warnings "Tenant '127' not found" de probes que pegan al IP del contenedor).

### Changed (breaking — internal)

- **`admin_organization_id` sin fallback global.** Eliminados `AppProperties.adminOrganizationId`, `AppConfig.getAdminOrganizationId()`, `IssuerProperties.getAdminOrganizationId()` y la línea `admin-organization-id: ${APP_ADMIN_ORGANIZATION_ID:...}` de `application.yml`. `APP_ADMIN_ORGANIZATION_ID` eliminada también del docker-compose del repo. `AccessTokenServiceImpl.resolveRole` y `PolicyContextFactory.resolveTenantAdmin` ahora usan `getStringOrThrow`. Rationale: el fallback enmascaraba tenants sin seed (p.ej. KPMG con `VATES-A78446333`). Tests afectados (`PolicyContextFactoryTest`, `AccessTokenServiceImplTest`, `AppConfigTest`, `IssuanceServiceImplTest`, `IssuancePdpServiceImplIntegrationTest`) actualizados para mockear `getStringOrThrow`.
- **`V1__Tenant_schema.sql`** ya no inserta `admin_organization_id = VATES-A15456585`. Cada tenant lo recibe per-tenant desde `seed-tenants[.stg].sql` (platform/sandbox/dome → Altia; kpmg → `VATES-A78446333`).
- **`V1__Public_schema.sql`** — display_name de `sandbox` → `"EUDIStack Sandbox"`.
- **Bootstrap API: contrato unificado con `X-Tenant-Id`.** El campo `tenant` del body `BootstrapRequest` se elimina; el tenant pasa por header (mismo convenio que el resto de la API). `TenantDomainWebFilter` ya no bypasea `/api/v1/bootstrap` — valida tenant y escribe el Reactor context. `BootstrapController` lee del context y ya no depende de `TenantRegistryService` (delega validación al filter). `BootstrapControllerTest` reescrito (4 tests); `TenantDomainWebFilterTest` incluye casos bootstrap con `X-Tenant-Id` válido/malformado.

### Migration

- Ejecutar `make reset && make up && make seed-tenants && make seed-verify` en local. El checksum mismatch de Flyway por editar `V1` requiere reset de volúmenes (aceptable antes del primer despliegue AWS).
- Scripts `seed-local-sd.py`, `seed-local-w3c.py`, `seed-local-sd-aws-stg.py`, `seed-ovh.py` actualizados para enviar `X-Tenant-Id` header y omitir el campo `tenant` del body.

## [3.2.2] - 2026-04-21

### Changed (EUDISTACK-166 / EUDI-064: unify tenant header name)

- **Breaking for internal callers.** Renamed the multi-tenancy header from `X-Tenant-Domain` to `X-Tenant-Id`.
  - `Constants.TENANT_DOMAIN_HEADER` → `Constants.TENANT_ID_HEADER` (value `"X-Tenant-Id"`).
  - `TenantDomainWebFilter` now reads `X-Tenant-Id` as the sole tenant header (Host header remains the fallback).
  - `RequireTenantMatchRule` error message and Javadoc updated.
  - Rationale: align with EUDI-064 US-01 (API Gateway route), prepare for AWS internal DNS going tenant-agnostic (Cloud Map namespace `{env}.eudistack.local`), and match the standard API Gateway convention. Decision taken with infra on 2026-04-21.
  - Callers that set the header explicitly (e.g. local dev via nginx, service-to-service clients) must update to `X-Tenant-Id`. No behaviour change when the tenant is resolved from the Host header.

## [3.2.1] - 2026-04-21

### Fixed (EUDI-065: cross-tenant TenantAdmin bypass)

- **`PolicyContextFactory.resolveTenantAdmin`** now validates that an `Onboarding/Execute` power's `domain` matches the current `tenantDomain` (case-insensitive). Previously the check only compared `function` + `action`, so a KPMG-issued credential (power domain = KPMG) was promoted to TenantAdmin when logging in on the DOME tenant, granting full Credential Manager access cross-tenant. Fixes the behaviour described in EUDI-065 §1.2 that was not enforced in the login PDP. Added unit tests covering the KPMG→DOME rejection and the case-insensitive accept.

## [3.2.0] - 2026-04-21

### Changed (EUDI-065: Unified LEAR issuance rule)

- **`RequireLearCredentialIssuanceRule`** replaces the OR-combined
  `RequireSignerIssuanceRule` + `RequireMandatorDelegationRule`. A single
  rule now covers `LEARCredentialEmployee` and `LEARCredentialMachine`
  issuance with three clauses: power base (`Onboarding/Execute`),
  escalation prevention (payload cannot delegate `Onboarding/Execute` nor
  `Certification/Attest`), and org scope (same-org or on-behalf — the
  latter only for TenantAdmin in `multi_org` tenants). SysAdmin keeps the
  full bypass.
- **`ProductOffering` removed as issuance gate.** It remains a valid
  delegable power that can appear in emitted credentials. The
  `delegation_function` field in `issuance_policy` is no longer read.
- **`PolicyContext.tenantType`** added (`simple` | `multi_org` |
  `platform`); `TenantRegistryService.getTenantType()` resolves it from
  `public.tenant_registry`.
- **`IssuancePdpServiceImpl`** dispatcher simplified: each profile now
  declares exactly one rule name. `PolicyEnforcer` OR-combination is no
  longer used for issuance.

See **ADR-002** (`docs/_shared/architecture/adr/adr-002-pdp-issuance-rules.md`
in `eudistack-platform-dev`) for rationale and full rule semantics.

### Removed (EUDI-065)

- `RequireSignerIssuanceRule` + its test — semantics folded into the
  unified rule with SysAdmin bypass.
- `RequireMandatorDelegationRule` — superseded by the org-scope clause
  of the unified rule.

## [3.1.0] - 2026-04-20

### Changed (EUDI-064: bootstrap is now cross-tenant)

- `POST /api/v1/bootstrap` requires a top-level `tenant` field in the
  request body. The bootstrap flow is administrative and
  cross-tenant: the caller declares the destination tenant explicitly
  instead of relying on hostname or `X-Tenant-Domain` header.
  `TenantDomainWebFilter` now bypasses `/api/v1/bootstrap`. Breaking
  change for direct callers; all in-tree scripts are updated in the
  `eudistack-platform-dev` repo in a sibling commit.

### Added (EUDI-065: Three-role authorization model)

- **`UserRole` enum and `AuthorizationContext` record** replacing `OrgContext` with explicit role (SYSADMIN, TENANT_ADMIN, LEAR) and `readOnly` flag.
- **SysAdmin detection via power** `organization/EUDISTACK/System/Administration` (no longer via `orgId == ADMIN_ORGANIZATION_ID`).
- **Platform tenant read-only view** — SysAdmin operating from `platform` tenant sees cross-tenant issuances with `tenant` field in DTO but cannot create/revoke/withdraw.
- **SysAdmin ↔ TenantAdmin equivalence** outside `platform` — from any other tenant, SysAdmin has same permissions as TenantAdmin (can write).
- **TenantAdmin role** — `organizationId == tenant.admin_organization_id` + domain power. Sees all issuances of the tenant, can create "on behalf", withdraw, revoke.
- **`admin_organization_id` per-tenant** in `tenant_config` table (seeded via Flyway V1).
- **`RequireOrganizationRule` bypass for TenantAdmin** — in addition to SysAdmin.
- **Withdraw authorization** — `canWrite()` check for platform tenant; ownership check for LEAR (only own org).
- **Flyway migration consolidation** — V1+V2+V3 merged into single `V1__Tenant_schema.sql` with `admin_organization_id` seed.

### Fixed (EUDI-064: AWS deployment readiness)

- **`TenantDomainWebFilter` hostname fallback** — When `X-Tenant-Domain` header is absent (AWS CloudFront + ALB path, no nginx to inject it), the tenant is now extracted from the first subdomain segment of the request host (e.g. `kpmg.eudistack.net` → `kpmg`). Header wins when both are present. Malformed identifiers return 400; unknown tenants continue to return 404; requests without a usable host still pass through for healthchecks. `RequireTenantMatchRule` error message updated accordingly.
- **`spring.webflux.base-path` re-enabled** (default `/issuer`, env `APP_CONTEXT_PATH`). Spring now mounts all WebFlux handlers under `/issuer` and `IssuerBaseUrlWebFilter` reads the same property to build public URLs — single source of truth. The previous R2DBC context-propagation regression is no longer reproducible; `reactor.context-propagation: auto` is sufficient. Unblocks AWS ALB + CloudFront deployments that do not inject `X-Forwarded-Prefix` and also removes the dependency on nginx prefix-strip in local dev.
- **MDC propagation across Reactor operators** — `tenantDomain` is now bridged from the Reactor subscriber context to SLF4J MDC via `Hooks.enableAutomaticContextPropagation()` plus a `ThreadLocalAccessor` registered in `MdcContextConfig`. The logback pattern `%X{tenantDomain:-}` now renders the tenant on every log line inside a reactive chain.

### Fixed (EUDI-064: Multi-tenant URL resolution)

- **`IssuerBaseUrlWebFilter`** reads context path from `ForwardedHeaderTransformer` instead of `X-Forwarded-Prefix` header (Spring WebFlux strips forwarded headers after processing).
- **`ParController` / `TokenController`** use `pathWithinApplication()` to avoid double `/issuer/issuer/` prefix in DPoP `htu` validation.

### Deprecated

- **`ADMIN_ORGANIZATION_ID` global env var** — Replaced by `tenant_config.admin_organization_id` per-tenant. Kept as fallback during migration.

### Changed

- **EUDI-013:** Migrate W3C credential JWT encoding to VCDM v2.0 (VC-JOSE-COSE)
  - Remove `vc` wrapper from JWT payload — credential properties are now root JWT claims
  - Set JOSE header `typ: vc+jwt` for W3C credentials and BitstringStatusListCredential
  - Remove duplicate JWT registered claims (`jti`, `sub`, `nbf`) from W3C credential payload
  - Rename credential_configuration_id: `learcredential.employee.w3c.1` → `.w3c.4`, `learcredential.machine.w3c.1` → `.w3c.3`
- **Actuator config migrated to Spring Boot 3.5 `access` API** — Replace deprecated `enabled-by-default: false` / `enabled: true` with `access: none` / `access: unrestricted`. No behavioral change.
- **IssuerFactory always remote** — Issuer identity is now always resolved from the QTSP via `credentials/info`, removing dependency on local certificate. (EUDI-023)
- **Credential offer email copy updated** — Update credential offer email copy in English and Spanish, remove the footer, and add a helper message above the wallet button.
- **Credential Offer Delivery**: Refactored the `CredentialOfferService` to support nested URL structures for the email delivery channel.
- **URL Encoding**: Implemented double URL encoding for the `credential_offer_uri` parameter to ensure that deep links are correctly preserved through the Wallet's authentication guards.
- **Protocol Standardization**: Updated the query parameter name from `credential_ofer_uri` to the OIDC standard `credential_offer_uri`.

### Added

- **Per-tenant CORS origins registry** — CORS allowed origins are now loaded from an external `cors-origins.yaml` file (configurable via `APP_CORS_ORIGINS_PATH`) and merged with the base origins (`APP_ISSUER_FRONTEND_URL`, `APP_WALLET_URL`). Supports multi-tenant deployments where each tenant has distinct frontend domains.
- **QTSP remote signing as default** — Default signing provider is now `altia-mock-qtsp` at `https://mock-qtsp.altia.fikua.com` via CSC API v2. Configuration loaded from `signing.remote-signature.*` in `application.yml` with env var overrides (`SIGNING_REMOTE_*`). (EUDI-023)
- **`signingOperation` config per QTSP** — Each QTSP declares whether it uses `sign-hash` or `sign-doc`. DelegatingSigningProvider routes by this field. No implicit fallbacks. (EUDI-023)
- **`RemoteSignatureProperties` / `SigningRuntimeConfigProperties`** — New `@ConfigurationProperties` records for default QTSP config from YAML. (EUDI-023)
- **Email notification on consent timeout** — Send an email notification when user consent times out during issuance.
- **SD-JWT mandate wrapper with nested disclosures** — SD-JWT credentials emit mandatee/mandator/power inside a `mandate` wrapper with `_sd` digests at the nested level. (EUDI-012)
- **RSA algorithm support in JAdES header** — RS256/384/512 and PS256 OIDs mapped for QTSPs with RSA certificates. (EUDI-023)

### Fixed

- **Signing algorithm hardcoded to ES256** — `JwsSignHashServiceImpl` now receives the signing algorithm OID from the QTSP certificate instead of hardcoding ES256. Fixes Status List Credentials signed with RSA certificates.
- **SD-JWT email delivery NPE** — Organization extraction for email notifications used hardcoded path `credential.get("mandator")` which doesn't exist in SD-JWT structure. Now reads `policy_extraction.mandator_path` from the credential profile dynamically.
- **Email error logging** — Added `doOnError` logging in `CredentialOfferServiceImpl` to surface the root cause of email failures instead of swallowing exceptions.
- **W3C issuer.id removed during credential build** — `GenericCredentialBuilder` was stripping the `id` field from the issuer object, causing Verifier schema validation failure (`required property 'id' not found`).
- **DPoP htu mismatch behind ALB** — PAR and Token controllers now derive the DPoP `htu` URI from the `IssuerBaseUrlWebFilter` context (which resolves `https://` correctly) instead of `exchange.getRequest().getURI()` (which returns `http://` behind an ALB that terminates TLS).

### Removed

- **Unused dependencies removed** — The following dependencies were removed from `build.gradle` as they are no longer needed:
  - `com.fasterxml.jackson.core:jackson-databind`
  - `com.fasterxml.jackson.datatype:jackson-datatype-jsr310`
  - `com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.2`
  - `io.micrometer:context-propagation`
  - `org.mockito:mockito-inline:5.2.0` (test)
  - `com.squareup.okhttp3:mockwebserver:4.12.0` (test)

- **`ISSUER_IDENTITY_JWT_CREDENTIAL` property** — Dead code. LEARCredentialMachine JWT for trust framework registration is no longer consumed. Identity is now managed via `privateKey` + `didKey` + X.509 certificate.
- **`InMemorySigningProvider`** — Local certificate-based signing removed. All signing is now via remote QTSP. (EUDI-023)
- **`DefaultSignerConfig` / `SignerConfig`** — Signer identity extracted from local cert no longer needed. (EUDI-023)
- **DSS legacy flow** — `getSignedDocumentDSS`, `signPath`, `type="server"`, `SIGNATURE_REMOTE_TYPE_SERVER` removed. (EUDI-023)
- **`SIGNING_CERTIFICATE_CERT_PATH` / `SIGNING_CERTIFICATE_KEY_PATH`** — Local certificate env vars removed. Use `SIGNING_REMOTE_*` instead. (EUDI-023)

## [3.0.0] - 2026-03-24

### Added

- **Dynamic URL resolution for multi-tenant deployment** — `IssuerBaseUrlWebFilter` extracts the public base URL from `X-Forwarded-*` headers and stores it in Reactor context. Metadata, credential offers, status list URLs, and token endpoints now derive URLs from the request instead of static `APP_URL`. Enables true multi-tenant with per-tenant subdomains. (EUDI-017)
- **ADOT Java Agent for CloudWatch X-Ray tracing** — Dockerfile includes AWS OpenTelemetry agent, activated via `JAVA_TOOL_OPTIONS`.
- **Reusable bootstrap token** — Bootstrap token can be reused for demo integrations instead of being single-use.
- **Dependabot config and PR template** — Automated dependency updates and standardized PR format.

### Fixed

- **Tenant validation uses `tenant` claim instead of `organizationIdentifier`** — `RequireTenantMatchRule` now compares the `tenant` claim (injected by the Verifier from OIDC client config) against the `X-Tenant-Domain` header (injected by nginx). Previously compared `mandator.organizationIdentifier`, conflating tenant and organization. B2B2C model: tenant groups organizations, organization groups users. `PolicyContext` gains `tokenTenant` field; `PolicyContextFactory` extracts the `tenant` claim. (EUDI-017)
- **Token issuer check order in `CustomAuthenticationManager`** — Check own issuer before verifier (`isIssuerBackendIssuer` before `isVerifierIssuer`) to avoid false match when both share the same base origin (subdomain routing on same port).
- **WIA PoP aud validation** — Resolves audience dynamically from `X-Forwarded-Host` instead of static `APP_URL`. (EUDI-017)
- **`RateLimitFilter` NPE with `ForwardedHeaderTransformer`** — Handle `getAddress() == null` on unresolved `InetSocketAddress` created by Spring's `ForwardedHeaderTransformer`. Uses `getHostString()` as fallback.

### Changed

- Refactor email templates: replace 6 per-language HTML files with 3 unified Thymeleaf i18n templates using locale-based resolution.
- Modernize email template design with consistent table-based layout, inline styles, and unified color scheme.
- Update EmailServiceImpl to use locale-aware Thymeleaf context instead of language-suffix template names.
- Clean up messages.properties: remove orphaned keys and add new i18n keys for all email templates.
- Restricted CORS allowed origins to prevent unauthorized cross-origin requests (SEC-001).
- Refactored CorsConfig to use AppConfig for dynamic origin loading.

## [v2.2.21](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.21)
### Added
- Add handling for missing exceptions in "GlobalExceptionHandler".
- Add tests for the new exception handling.

## [v2.2.20](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.20)
### Added
- Add support for sign hash implementation.
- Add configuration signing endpoint.

## [v2.2.19](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.19)
### Added
- Add support for sign hash implementation.
- Add configuration signing endpoint.

## [v2.2.18](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.18)
### Changed
- Add cnf to the credential.
- Add CORS public permissions for vci issuances paths.

## [v2.2.17](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.17)
### Added
- Add support for multiple signing keys in the SPI implementation.
- Add configuration properties to specify the signing key alias and credentials.

## [v2.2.16](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.16)
### Added
- SPI interface for credential signing.
- Baseline SPI implementation for local and remote signing.

### Changed
- Refactoring of the signing logic to utilize the SPI


## [v2.2.15](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.15)
### Changed
- Updated Java and Spring Boot version.

## [v2.2.14](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.14)
### Changed
- Updated project-name.

## [v2.2.13](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.13)
### Changed
- Create bitstring-encoded lists using MSB-first ordering.

## [v2.2.12](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.12)
### Changed
- Update Failure case in Notification Endpoint.

## [v2.2.10](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.10)
### Fixed
- Don't send mail when Deferred Credential fails.

## [v2.2.9](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.9)
### Added
- Notification Endpoint implemented

## [v2.2.8](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.8)
### Changed
- Update refresh token.
- Update deferred credential flow.

## [v2.2.7](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.7)
### Added
- Cryptographic Binding implemented

## [v2.2.6](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.6)
### Changed
- Set vault's secret mounts as environment variable.
- Remove 'actuator/' path from health and prometheus base path.

## [v2.2.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.5)
### Fixed
- LEARCredentials mandator validation by OrgId.

## [v2.2.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.4)
### Added
- LEARCredentialMachine async signature.

## [v2.2.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.3)
### Fixed
- Prevent retrying the signature process when the credential procedure is not in PEND_SIGNATURE status.

## [v2.2.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.2)
### Changed
- Add org ID validation for notification and async signature flows.

## [v2.2.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.1)
### Added
- Add environment variable `sys-admin`, use it instead of constant DEFAULT_ORGANIZATION_NAME, which was used in email templates.

## [v2.2.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.0)
### Added
- Make admin organization identifier configurable (add adminOrganizationId env variable).
- When fetching procedures, if the authenticated user is an admin, fetch across all organizations.
- When fetching a procedure, if the authenticated user is an admin, don't restrict by organization.
- Enable R2DBC auditing to auto-populate `created_at`, `updated_at`, `created_by`, and `updated_by`.
- Resolve auditing principal from the JWT access token (prefer ID token when available).

### Changed
- For Employee and Machine credentials, set the `organization_identifier` field with the mandator email.
- `updated_at` in `CredentialProcedure` and related entities is now managed automatically by Spring Data (no manual updates).
- `subject_email` in `CredentialProcedure` and related entities has been renamed to `email`.
- In "activate credential" email Spanish template, replace "Estimado/a ," by "Hola,"

### Fixed
- Change deprecated build image openjdk:17-alpine by eclipse-temurin:17-jdk-alpine
- Send signature failure emails to the authenticated requester’s email, not the credential mandator’s updated email.

### Removed
- Sign controller (unused).

## [v2.1.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.1.1)
### Added
- Get default language from configuration, use it to translate messages (emails, PIN description).

## [v2.1.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.1.0)
### Changed
- If LEARCredentialMachine issuance presubmitted data contains credential_owner_email, use it as owner email.
- Don't include name in emails.

### Fixed
- When sending Label Credential to VC URI, send it encoded.

## [v2.0.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.0.0)
### Added
- Label credential issuance.
- LEARCredentialMachine issuance.
- Sign access request.
- Revocation endpoint.
- Revoke and expired credential notification.
- Handle error when sending PIN and when serializing credential.
- Handle errors in security chains flow.

### Changed
- Adapt endpoints to oid4vci.
- Refactor SecurityConfig credential issuer filters.
- Standardize error handling to RFC 7807 across all endpoints.
- Move GlobalExceptionHandler to shared module and add specific ControllerAdvice for each domain.
- Remove unused exceptions.



## [v1.7.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.7.0)
### Added
- Added remote signature configuration.

## [v1.6.9](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.9)
### Fixed
- Store Verifiable certification metadata after issuance
- Send Verifiable certification to responseUri after remote signature
- Modify the message sent after successful remote signature; adapt it to Verifiable Certification

## [v1.6.8](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.8)
### Fixed
- Error on credential request contract.

## [v1.6.7](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.7)
### Fixed
- When updating transaction code, delete previous one

## [v1.6.6](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.6)
### Fixed
- OID4VCI cors configuration.

## [v1.6.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.5)
### Fixed
- Refactor configs.

## [v1.6.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.4)
### Feature
- Migrate from Keycloak extension.

## [v1.6.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.3)
### Fixed
- Problem with public cors configuration.

## [v1.6.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.2)
### Fixed
- Separate internal and external issuing endpoints to be able to apply different authentication filters.
- Use M2M token when issuing Verifiable Certifications.

## [v1.6.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.1)
### Fixed
- Handle error during mail sending on the credential offer.

## [v1.6.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.0)
### Changed
- Added role claim and validations.
- Modified authenticator to allow access exclusively with the "LEAR" role, returning a 401 error for any other role.

## [v1.5.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.2)
### Fixed
- Fixed parsing learCredentialEmployee

## [v1.5.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.1)
### Fixed
- Fixed parsing certificates

## [v1.5.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.0)
### Added
- Added support to sign the credential with an external service.
- Now issuer is created with data from the external service.
- Error handling for the external service flows.
- Added controller to handle manual signature after failed attempts.

## [v1.4.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.3)
### Fixed
- Solve error on schema importation for flyway migration.

## [v1.4.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.1)
### Fixed
- Solve error during credential serialization.

## [v1.4.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.0)
### Added
- Compatibility with LEARCredentialMachine to issue LEARCredentialEmployee.

## [v1.3.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.3.0)
### Changed
- The issuer now issues only LearCredentialEmployee v2.

## [v1.2.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.5)
### Changed
- Changing environment variable for wallet knowledge redirection to email.
- Changed email template implementation for better compatibility.

## [v1.2.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.4)
### Changed
- Fix a problem with a cors endpoint.

## [v1.2.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.3)
### Added
- Add cors configuration for externals clients on the issuance endpoint.

### Changed
- Change email template styles, improve compatibility accross different email providers (e.g., Gmail)


## [v1.2.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.2)
### Added
- Add scheduled task to set EXPIRED status to credentials that have expired.

## [v1.2.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.1)
### Added
- Add support for requesting a fresh QR code if the previous one has expired or was an error during the proccess of

## [v1.2.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.0)
### Added
- Validation of authentication for issuance against the verifier.
- Verifiable Certifications issuance and sending to response_uri.
### Changed
- List credentials in order from newest to oldest.

## [v1.1.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.3)
### Changed
- Change the Credential Offer email template

## [v1.1.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.2)
### Changed
- Change the order of the received email from the pin during the issuance of a credential.

## [v1.1.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.1)
### Fixed
- Fixed LEARCredentialEmployee data model. Implement W3C DATA model v2.0 (validFrom, validUntil). 

## v1.1.0
### Added
- LEARCredentialEmployee issuance in a synchronous way.
- DOME Trust Framework integration to register issuers and participants.
### Changed
- Issuances API to support various issuance types.

