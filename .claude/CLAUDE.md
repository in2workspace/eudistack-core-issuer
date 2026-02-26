# CLAUDE.md - Issuer Core Backend

## Project Overview

Spring Boot 3.5.10 + WebFlux (reactive) implementation of an OID4VCI Credential Issuer.
Package: `es.in2.issuer`, version 2.2.19. Java 25, Gradle, PostgreSQL (R2DBC), Flyway.

## Architecture

Hexagonal (Ports & Adapters) + DDD. Four bounded contexts:

- **oidc4vci/** - OID4VCI protocol endpoints (metadata, token, credential, offer, deferred, notification)
- **backoffice/** - Admin UI backend (issuance management, signature config, security config)
- **signing/** - Pluggable signing SPI (InMemory, CscSignHash, CscSignDoc)
- **statuslist/** - Credential revocation via Bitstring Status Lists
- **shared/** - Cross-cutting: models, crypto, factories, security services

Each context follows: `domain/` (model, service, exception, util) → `application/` (workflow, policies) → `infrastructure/` (controller, config, adapter, repository).

## Key Technical Decisions

- **Reactive stack**: WebFlux + R2DBC (no blocking, no JPA)
- **Signing SPI**: `SigningProvider` interface with runtime provider selection via `DelegatingSigningProvider`
- **Credential format**: Currently only `jwt_vc_json` (W3C VCDM v2.0)
- **Grant type**: Currently only `pre-authorized_code` (+ `refresh_token`)
- **Authentication**: Dual filter chain — OID4VCI via `CustomAuthenticationManager` (Verifier tokens), Backoffice via Keycloak JWT decoder
- **Credential definitions**: Hardcoded in Java Factory classes (LEARCredentialEmployee, LEARCredentialMachine, LabelCredential)

## Documentation Index

All design & implementation documents are in `.claude/docs/`:

- [current-architecture.md](docs/current-architecture.md) - Complete codebase audit
- [gap-analysis.md](docs/gap-analysis.md) - Current state vs OID4VCI 1.0 Final target
- [keycloak-removal.md](docs/keycloak-removal.md) - Plan to eliminate Keycloak dependency
- [policy-restructuring.md](docs/policy-restructuring.md) - PDP consolidation plan
- [credential-json-schema.md](docs/credential-json-schema.md) - JSON Schema-driven credentials
- [sd-jwt-implementation.md](docs/sd-jwt-implementation.md) - SD-JWT format implementation
- [auth-code-flow.md](docs/auth-code-flow.md) - Authorization Code + Issuer-Initiated flow
- [implementation-roadmap.md](docs/implementation-roadmap.md) - Execution order & dependencies

## Reference: fikua-lab

The reference implementation (fikua-lab) lives at `/Users/ocanades/Projects/fikua/fikua-lab`.
Its technical document is at `docs/fikua-lab-dt.md`. Key differences from this repo:

- fikua-lab uses Javalin + JDBC (synchronous), this repo uses Spring WebFlux + R2DBC (reactive)
- fikua-lab has `fikua-core` as a pure protocol library with zero dependencies
- fikua-lab supports both `dc+sd-jwt` and `mso_mdoc`, this repo only supports `jwt_vc_json`
- fikua-lab implements full HAIP profile (DPoP, PAR, PKCE, WIA), this repo does not

## Local Development

### Option 1: IDE + Docker (fastest iteration)

```bash
cd docker
docker compose up -d postgres mailhog    # DB + email catcher only
# Then run backend from IDE with profile: local
# (SPRING_PROFILES_ACTIVE=local or --spring.profiles.active=local)
# Angular frontend:
cd ../../in2-eudistack-issuer-core-ui && npm start
```

### Option 2: Full Docker stack

```bash
cd docker
docker compose up -d                       # DB + backend + mailhog
docker compose --profile ui up -d          # + Angular frontend
docker compose up -d --build backend       # rebuild after code changes
```

### Option 3: Build only

```bash
./gradlew build          # Build + tests
./gradlew test           # 161 test files, 1.56:1 test-to-code ratio
./gradlew bootRun        # Run (needs PostgreSQL + env vars)
```

### Services

| Service | URL | Purpose |
|---------|-----|---------|
| Backend | http://localhost:8080 | Issuer API |
| Frontend | http://localhost:4200 | Angular Issuer Portal |
| PostgreSQL | localhost:5432 | Database (issuer/issuer/issuer) |
| MailHog UI | http://localhost:8025 | Email viewer (captures all mail) |
| Swagger UI | http://localhost:8080/springdoc/swagger-ui.html | API docs |

## Critical Paths (do not break)

1. Pre-authorized_code flow: Credential Offer → Token (pre-auth + tx_code) → Credential
2. W3C VCDM v2.0 `jwt_vc_json` format for LEARCredentialEmployee/Machine/Label
3. Signing SPI: InMemory (dev) / CscSignHash (production)
4. Status List revocation
5. Deferred credential flow
