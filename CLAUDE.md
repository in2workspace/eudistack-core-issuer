# Credential Issuer — Repo Guide for Claude

> **Per-repo CLAUDE.md.** Loaded only when working inside this repo. The
> SDD Constitution lives in
> `../eudistack-platform-dev/CLAUDE.md`. Add it via
> `--add-dir ../eudistack-platform-dev` when you need spec/architecture
> context.

## Identity

Java 25 + Spring Boot 3.5 + WebFlux implementation of the EUDIStack
**Credential Issuer (CORE / Foundations)**. Implements OID4VCI 1.0 +
SD-JWT VC + Pre-Authorized Code flow with PIN. Stores emitted
credentials in PostgreSQL (R2DBC). Signs via remote DSS (CSC API v2.0).

Repo group: `com.eudistack` · current version: see `build.gradle`.

## Tech stack

- **Java 25** (Gradle toolchain)
- **Spring Boot 3.5.11** + WebFlux (reactive)
- **R2DBC** + PostgreSQL (schema-per-tenant)
- **Flyway** for migrations
- **Nimbus JOSE+JWT** + BouncyCastle for crypto
- **WebClient** for outbound HTTP (Verifier, QTSP, Trust Framework)
- **Testcontainers** for integration tests
- **Checkstyle** + **JaCoCo** wired into CI (`./gradlew build` runs them via `check`).
- **OWASP dependency-check** plugin available locally (`./gradlew dependencyCheckAnalyze`); not yet bound to CI.

## Architecture (hexagonal)

```text
src/main/java/es/in2/issuer/backend/
├── issuance/           ← Credential issuance use cases
├── oidc4vci/           ← OID4VCI protocol adapters
├── signing/            ← DSS / QTSP signing flows
├── statuslist/         ← Token Status List endpoints
└── shared/             ← Cross-cutting (tenant context, security, utils)
```

Each module follows hexagonal layers:

- `domain/` — entities, value objects, domain services (no Spring imports)
- `application/` — use cases, ports (interfaces)
- `infrastructure/` — adapters (controllers, R2DBC, WebClient, config)

Strict rules in `../eudistack-platform-dev/.claude/rules/hexagonal-discipline.md`.

## Multi-tenancy

- Tenant resolved from `X-Tenant-Id` header by `TenantDomainWebFilter` and stored under the `tenantDomain` key in the Reactor `Context` (never `ThreadLocal`).
- One PostgreSQL schema per tenant; `TenantAwareConnectionFactoryDecorator` issues `SET search_path TO <tenant><suffix>, public` when a connection is borrowed (no explicit reset on release — connections are short-lived and re-set per borrow).
- See `../eudistack-platform-dev/.claude/rules/tenant-isolation.md`.

## Common commands

> **Dev stack runs in Docker** via `make up` from `eudistack-platform-dev`. Do NOT `./mvnw spring-boot:run` or `./gradlew bootRun` for normal dev — the stack needs nginx multi-tenant routing.

| Task | Command |
|------|---------|
| Compile | `./gradlew compileJava` |
| Unit + integration tests (Testcontainers `*IT`) | `./gradlew test` |
| Full check (compile + tests + checkstyle + jacoco) | `./gradlew check` |
| Rebuild Docker image for stack | `cd ../eudistack-platform-dev && make rebuild-issuer-service` |
| Tail logs in stack | `cd ../eudistack-platform-dev && make logs-issuer` |
| OWASP dependency check (local only) | `./gradlew dependencyCheckAnalyze` |
| Format check | `./gradlew checkstyleMain checkstyleTest` |

## Testing conventions

- `*Test.java` — unit (JUnit 5 + Mockito, no Spring).
- `*IT.java` — integration (Spring + Testcontainers Postgres). Runs in the same `test` task — there is no separate `integrationTest` task / source set.
- Naming: `Class_methodUnderTest_expectedBehavior`.
- WebFlux endpoints: `WebTestClient`.
- One assertion concept per test.
- **CI JaCoCo gate (enforced):** 40% overall, 60% changed files (`.github/workflows/ci.yml` via `madrapps/jacoco-report`). Aim higher (≥80% on new code) but the build only fails below those numbers.

## Protocols implemented

- **OID4VCI 1.0** — Credential Issuance (Pre-Authorized Code + Authorization Code).
- **SD-JWT VC** (RFC 9901) — Selective Disclosure JWT for verifiable credentials.
- **Token Status List** — Revocation.
- **DPoP** (RFC 9449) — Proof-of-Possession on `/token` and `/credential`.
- **PKCE** (RFC 7636) — Authorization code protection.
- **CSC API v2.0** — Cloud signature consortium (QTSP signing).

Normative invariants in
`../eudistack-platform-dev/.claude/rules/protocol-compliance.md`.

## Code style

- Lombok for constructors / getters where it removes ceremony.
- Constructor injection only — never `@Autowired` on fields.
- Package-by-feature inside hexagonal layers.
- Reactive: every blocking call wrapped in `Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())`.
- Logging: SLF4J via Lombok `@Slf4j`. Structured fields, no `String.format` in log messages.
- No `System.out.println`. Never.

## Where to find specs

The functional and technical specs for any Story (`EUDISTACK-MMM`) live in
`../eudistack-platform-dev/docs/EUDISTACK-NNN-*/EUDISTACK-MMM/`. When
implementing, read:

1. `user-story.md` — the *what* and *why*.
2. `acceptance-criteria.md` — the gates.
3. `technical-design.md` — the *how* (this is where C3-C4 detail lives).
4. `tasks.md` — the breakdown + closing C1–C5.

## Git workflow

- **Squash merge to `main` always.** One commit per logical change.
- After squash-merge: `git branch -D <branch>` (force; the branch shows unmerged).
- Conventional Commits + Story footer (see `commit-conventions` skill).
- Branch-guard hook in platform-dev blocks direct commits to `main`.

## References

- Constitution: [`../eudistack-platform-dev/CLAUDE.md`](../eudistack-platform-dev/CLAUDE.md)
- SAD: [`../eudistack-platform-dev/docs/_shared/architecture/sad.md`](../eudistack-platform-dev/docs/_shared/architecture/sad.md)
- Skills: `../eudistack-platform-dev/.claude/skills/java-spring-hexagonal/`, `code-review-checklist/`, `commit-conventions/`
- Rules: `../eudistack-platform-dev/.claude/rules/{hexagonal-discipline,tenant-isolation,protocol-compliance}.md`
