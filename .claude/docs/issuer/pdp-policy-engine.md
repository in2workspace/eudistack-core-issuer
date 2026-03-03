# PDP Policy Engine — Spec & OPA/Rego Migration Path

> **Status**: Implemented (PolicyRule-based, Java)
> **Last updated**: 2026-03

---

## Overview

The Issuer backend has three independent Policy Decision Points (PDPs), one per authorization domain. Each PDP validates a JWT access token and evaluates composable `PolicyRule` implementations with AND/OR semantics.

The current implementation is **pure Java**. The architecture is designed so that each `PolicyRule` can be replaced by an OPA (Open Policy Agent) + Rego call with minimal surface area changes.

---

## Current implementation

### Components

```
shared/domain/policy/
├── PolicyRule<T>           — @FunctionalInterface: evaluate(ctx, target) → Mono<Void>
├── PolicyContext           — Pre-parsed JWT context (org, powers, sysAdmin, tenantDomain)
├── PolicyContextFactory    — Parses access token → PolicyContext
├── PolicyEnforcer          — Composes rules: enforce() = AND, enforceAny() = OR
└── rules/
    ├── RequirePowerRule                   — hasPower(function, action) with domain check
    ├── RequireOrganizationRule            — orgId == targetOrgId (with sysAdmin bypass)
    ├── RequireSignerIssuanceRule          — sysAdmin + Onboarding/Execute
    ├── RequireMandatorEmployeeIssuanceRule — org match + powers limited to ProductOffering
    ├── RequireMandatorMachineIssuanceRule  — org match + powers limited to Onboarding
    └── RequireCertificationIssuanceRule   — Certification/Attest on bearer + x-id-token
```

### PDP services

| Service | Guards | Location |
|---------|--------|----------|
| `IssuancePdpServiceImpl` | `POST /vci/v1/issuances` | `shared/infrastructure/config/security/service/impl/` |
| `BackofficePdpServiceImpl` | Sign credential, send reminder | `backoffice/application/workflow/policies/impl/` |
| `StatusListPdpServiceImpl` | Revoke credential | `statuslist/application/workflow/policies/impl/` |

### `PolicyContext` (pre-parsed auth context)

```java
record PolicyContext(
    String organizationIdentifier,  // from mandator.organizationIdentifier in LEARCredential
    List<Power> powers,             // from credentialSubject.mandate.power[]
    LEARCredential credential,      // full parsed credential
    String credentialType,          // e.g. "LEARCredentialEmployee"
    boolean sysAdmin,               // org == APP_ADMIN_ORGANIZATION_ID + Onboarding/Execute
    String tenantDomain             // from Reactor context (host-based multi-tenancy)
)
```

### `PolicyRule<T>` contract

```java
@FunctionalInterface
interface PolicyRule<T> {
    Mono<Void> evaluate(PolicyContext context, T target);
    // Mono.empty() = authorized
    // Mono.error(InsufficientPermissionException) = denied
}
```

### `PolicyEnforcer` composition

```java
// AND: all rules must pass (fails fast)
enforcer.enforce(ctx, payload, ruleA, ruleB, ruleC);

// OR: at least one rule must pass
enforcer.enforceAny(ctx, payload, "error message", ruleA, ruleB);
```

---

## Authorization policies (current)

### 1. Issuance (`IssuancePdpServiceImpl`)

Input: JWT access token + `credential_configuration_id` + payload + optional `x-id-token`

```
resolve credentialType from profile (credential_configuration_id → logical type)
build PolicyContext from token

switch(credentialType):
  LEARCredentialEmployee →
    enforceAny(RequireSignerIssuanceRule, RequireMandatorEmployeeIssuanceRule)

  LEARCredentialMachine →
    enforceAny(RequireSignerIssuanceRule, RequireMandatorMachineIssuanceRule)

  gx:LabelCredential →
    requireCertificationIssuanceRule.evaluate(ctx, idToken)

  default → InsufficientPermissionException("Unsupported schema")
```

#### Rule details

| Rule | What it checks |
|------|---------------|
| `RequireSignerIssuanceRule` | `sysAdmin == true` AND has `Onboarding / Execute` |
| `RequireMandatorEmployeeIssuanceRule` | `mandator.org == payload.mandator.org` AND all powers have `function == ProductOffering` |
| `RequireMandatorMachineIssuanceRule` | `mandator.org == payload.mandator.org` AND all powers have `function == Onboarding` |
| `RequireCertificationIssuanceRule` | Bearer LEARCredentialMachine has `Certification / Attest` AND x-id-token LEARCredentialEmployee has `Certification / Attest` |

### 2. Backoffice (`BackofficePdpServiceImpl`)

Input: JWT access token + `procedureId`

```
parse token → role must be LEAR
build PolicyContext from token

if sysAdmin:
  allow (skip DB lookup)
else:
  enforce(RequirePowerRule(Onboarding, Execute), RequireOrganizationRule(procedure.orgId))
```

### 3. Revocation (`StatusListPdpServiceImpl`)

Input: JWT access token + credential (status check)

```
status must be VALID

parse token → role must be LEAR
build PolicyContext from token

if sysAdmin:
  allow
else:
  enforce(RequirePowerRule(Onboarding, Execute), RequireOrganizationRule(credential.orgId))
```

### SysAdmin definition

A user is SysAdmin when **both**:
1. `mandator.organizationIdentifier` == `APP_ADMIN_ORGANIZATION_ID` (env var)
2. Has power `function == Onboarding` AND `action == Execute`

SysAdmin bypasses organization match and power checks in Backoffice and StatusList. No SysAdmin bypass exists for LabelCredential issuance.

---

## OPA/Rego migration path

### Why OPA?

| Concern | Java `PolicyRule` | OPA + Rego |
|---------|------------------|-----------|
| Policy changes | Require recompile + deploy | Hot-reload or API push |
| Multi-system reuse | Copy-paste | Single policy server, multiple callers |
| Auditing | Custom logging | Built-in decision log |
| Testing | JUnit | `opa test` |
| Complexity ceiling | Medium (Java is verbose) | High (Rego designed for policies) |

When to migrate: when the same policies need to be enforced in >1 system (e.g. verifier, wallet backend, issuer) or when policy update frequency exceeds release cadence.

---

### Architecture after OPA migration

```
 Issuer backend                OPA sidecar / server
 ──────────────               ──────────────────────
 IssuancePdpServiceImpl  ───► POST /v1/data/issuer/issuance/allow
    (sends input JSON)         (evaluates Rego policy)
                          ◄─── { "result": true/false, "reason": "..." }
```

OPA can run as:
- **Sidecar** in the same pod (localhost call, no network latency)
- **Standalone service** (shared across systems)
- **Compiled WASM** embedded in the JVM (no network at all)

---

### Input document shape (Rego)

```json
{
  "input": {
    "credential_type": "LEARCredentialEmployee",
    "tenant_domain": "altia.eudistack.eu",
    "token": {
      "organization_identifier": "VATES-B81967643",
      "powers": [
        { "function": "Onboarding", "action": ["Create", "Update", "Execute"], "domain": "altia.eudistack.eu" }
      ],
      "credential_type": "LEARCredentialEmployee",
      "sys_admin": false
    },
    "payload": {
      "mandator": { "organizationIdentifier": "VATES-B81967643" },
      "power": [
        { "function": "ProductOffering", "action": "Execute" }
      ]
    },
    "id_token": null
  }
}
```

---

### Rego policy (illustrative)

```rego
package issuer.issuance

import rego.v1

default allow := false
default reason := "Unauthorized"

# --- SysAdmin path ---
allow if {
    input.credential_type in {"LEARCredentialEmployee", "LEARCredentialMachine"}
    is_sys_admin
    has_power("Onboarding", "Execute")
}

# --- Mandator delegation: Employee ---
allow if {
    input.credential_type == "LEARCredentialEmployee"
    org_match
    has_power("Onboarding", "Execute")
    all_payload_powers_match_function("ProductOffering")
}

# --- Mandator delegation: Machine ---
allow if {
    input.credential_type == "LEARCredentialMachine"
    org_match
    has_power("Onboarding", "Execute")
    all_payload_powers_match_function("Onboarding")
}

# --- LabelCredential ---
allow if {
    input.credential_type == "gx:LabelCredential"
    bearer_has_certification_attest
    id_token_has_certification_attest
}

# --- Helpers ---
is_sys_admin if input.token.sys_admin == true

org_match if {
    input.token.organization_identifier == input.payload.mandator.organizationIdentifier
}

has_power(fn, action) if {
    some p in input.token.powers
    p.function == fn
    action in p.action
    p.domain == input.tenant_domain
}

all_payload_powers_match_function(fn) if {
    every p in input.payload.power { p.function == fn }
}

bearer_has_certification_attest if {
    has_power_in_token(input.token, "Certification", "Attest")
}

id_token_has_certification_attest if {
    has_power_in_token(input.id_token, "Certification", "Attest")
}

has_power_in_token(token, fn, action) if {
    some p in token.powers
    p.function == fn
    action in p.action
}
```

---

### Java adapter (minimal surface)

When migrating, only the PDP service implementations change — `PolicyRule`, `PolicyContext`, `PolicyContextFactory`, and `PolicyEnforcer` are **deleted**. The callers (`CredentialIssuanceWorkflowImpl`, `BackofficeWorkflow`, `RevocationWorkflow`) stay untouched.

```java
// OpaIssuancePdpServiceImpl replaces IssuancePdpServiceImpl
@Service
public class OpaIssuancePdpServiceImpl implements IssuancePdpService {

    private final WebClient opaClient;  // configured for localhost:8181

    @Override
    public Mono<Void> authorize(String token, String configId, JsonNode payload, String idToken) {
        return buildOpaInput(token, configId, payload, idToken)
                .flatMap(input -> opaClient.post()
                        .uri("/v1/data/issuer/issuance/allow")
                        .bodyValue(Map.of("input", input))
                        .retrieve()
                        .bodyToMono(OpaResult.class))
                .flatMap(result -> result.allow()
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException(result.reason())));
    }
}
```

Only **3 files** change:
1. `OpaIssuancePdpServiceImpl` replaces `IssuancePdpServiceImpl`
2. `OpaBackofficePdpServiceImpl` replaces `BackofficePdpServiceImpl`
3. `OpaStatusListPdpServiceImpl` replaces `StatusListPdpServiceImpl`

The `PolicyRule` hierarchy is deleted entirely. Zero callers need updating.

---

### Migration checklist (when needed)

- [ ] Add OPA sidecar to `compose.yaml` (or Helm chart)
- [ ] Create `policies/issuer/` directory with Rego files
- [ ] Add `opa test` to CI pipeline
- [ ] Write `OpaIssuancePdpServiceImpl`, `OpaBackofficePdpServiceImpl`, `OpaStatusListPdpServiceImpl`
- [ ] Add `WebClient` bean configured for OPA (`localhost:8181` or service URL)
- [ ] Feature flag / Spring profile switch (`@ConditionalOnProperty("pdp.engine")`)
- [ ] Delete `PolicyRule`, `PolicyContext`, `PolicyContextFactory`, `PolicyEnforcer`, `rules/`
- [ ] Validate with integration tests against OPA sidecar

---

## Known gaps in current implementation

1. **Power domain check** not enforced in Backoffice/StatusList (`RequirePowerRule` checks domain, but `hasPower()` in `PolicyContext` does not for the issuance signer check)
2. **x-id-token signature verification** delegates to the external Verifier service, adding a network dependency to the certification issuance policy
3. **No decision log** — policy decisions are not persisted for audit
4. **No policy versioning** — policy changes require code deployment