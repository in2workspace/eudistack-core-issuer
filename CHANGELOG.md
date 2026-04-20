# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- **`IssuerBaseUrlWebFilter` context-path from config** — New `app.context-path` property (env `APP_CONTEXT_PATH`, default `/issuer`) is now authoritative for the public context-path. The previous `request.getPath().contextPath()` path (fed by `X-Forwarded-Prefix` from nginx) is kept as a fallback when the property is empty, preserving local dev. Unblocks AWS ALB deployments that do not inject `X-Forwarded-Prefix`. `spring.webflux.base-path` remains disabled due to the R2DBC context-propagation issue.
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

### Fixed

- **DPoP htu mismatch behind ALB** — PAR and Token controllers now derive the DPoP `htu` URI from the `IssuerBaseUrlWebFilter` context (which resolves `https://` correctly) instead of `exchange.getRequest().getURI()` (which returns `http://` behind an ALB that terminates TLS).

### Changed

- **Actuator config migrated to Spring Boot 3.5 `access` API** — Replace deprecated `enabled-by-default: false` / `enabled: true` with `access: none` / `access: unrestricted`. No behavioral change.
- **IssuerFactory always remote** — Issuer identity is now always resolved from the QTSP via `credentials/info`, removing dependency on local certificate. (EUDI-023)

### Removed

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

