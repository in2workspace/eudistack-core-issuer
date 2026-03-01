# Issuer — Authorization Policies

This document describes the authorization policies enforced by the Issuer backend. All authorization logic lives in the PDP (Policy Decision Point) layer and in composable `PolicyRule` implementations.

## SysAdmin

A user is considered **SysAdmin** when **both** conditions are met:

1. The `mandator.organizationIdentifier` of their LEARCredential matches the value configured in `APP_ADMIN_ORGANIZATION_ID`.
2. Their credential includes the power `Onboarding / Execute`.

A SysAdmin can operate across all organizations without restrictions. A user from the admin organization that does **not** have `Onboarding / Execute` is treated as a regular user.

---

## 1. Backoffice (sign, send reminder)

**PDP:** `BackofficePdpServiceImpl`
**Actions:** Sign a credential, send a reminder to the mandatee.

### Rules (all must pass)

1. **Required power:** The user must have `Onboarding / Execute` with a domain matching the tenant. A SysAdmin bypasses this check.
2. **Organization match:** The user's `mandator.organizationIdentifier` must match the `organizationIdentifier` stored in the credential procedure. This ensures a user from Org-A cannot sign credentials belonging to Org-B. A SysAdmin bypasses this check (and the database lookup is skipped entirely as an optimization).

---

## 2. Revocation

**PDP:** `StatusListPdpServiceImpl`

### 2a. User-initiated revocation

**Action:** A backoffice user revokes a credential.

#### Rules (all must pass)

1. **Status check:** The credential must currently be in `VALID` status.
2. **Required power:** Same as Backoffice: `Onboarding / Execute` with tenant domain. SysAdmin bypass.
3. **Organization match:** Same as Backoffice: the user's organization must match the credential's organization. SysAdmin bypass.

### 2b. System-initiated revocation

**Action:** The system automatically revokes a credential when the wallet sends a `CREDENTIAL_DELETED` notification (OIDC4VCI notification endpoint). The holder has deleted the credential from their wallet.

#### Rules

1. **Status check:** The credential must currently be in `VALID` status.

No user authentication is required because this is a system-to-system operation triggered by the wallet holder's action.

---

## 3. Credential issuance

**PDP:** `IssuancePdpServiceImpl`

### Pre-validation: signer credential type

Before evaluating issuance policies, the system validates that the signer's credential type is compatible with the schema being issued:

| Schema requested | Required signer credential type |
|---|---|
| `LEARCredentialEmployee` | `LEARCredentialEmployee` (preferred) or `LEARCredentialMachine` (M2M onboarding service) |
| `LEARCredentialMachine` | `LEARCredentialEmployee` (mandatory) |
| `LabelCredential` | `LEARCredentialMachine` (mandatory) + `LEARCredentialEmployee` as `x-id-token` |

### 3a. LEARCredentialEmployee issuance

**At least one** of the following paths must pass:

#### Path A — SysAdmin issuance

A SysAdmin can issue any `LEARCredentialEmployee` without restrictions.

- Condition: `sysAdmin == true` and the credential has `Onboarding / Execute` power.

#### Path B — Mandator delegation

A regular user can issue `LEARCredentialEmployee` credentials for their own organization, with limitations on the powers that can be delegated.

- The signer's credential must include `Onboarding / Execute` power.
- The payload's `mandator.organizationIdentifier` must match the signer's `mandator.organizationIdentifier`. A user from Org-A cannot issue credentials for Org-B.
- All powers in the issued credential must have `function == "ProductOffering"`. This prevents a user from delegating `Onboarding / Execute` or `Certification` powers.

### 3b. LEARCredentialMachine issuance

**At least one** of the following paths must pass:

#### Path A — SysAdmin issuance

Same as 3a Path A. A SysAdmin can issue any `LEARCredentialMachine`.

#### Path B — Mandator delegation

Same principle as 3a Path B, adapted for machine credentials:

- The signer's credential must include `Onboarding / Execute` power.
- The payload's `mandator.organizationIdentifier` must match the signer's `mandator.organizationIdentifier`.
- All powers in the issued credential must have `function == "Onboarding"`.

### 3c. LabelCredential (verifiable certification) issuance

A `LabelCredential` represents a verifiable certification (e.g., gx:LabelCredential). Issuance requires two credentials:

1. **Signer credential** (`LEARCredentialMachine` presented as bearer token): Must include a power with `function == "Certification"` and `action == "Attest"`.
2. **ID token** (`LEARCredentialEmployee` presented as `x-id-token` header): Its signature is verified (without expiration check), then the credential inside is parsed and must also include `Certification / Attest` power.

Both conditions must be met. There is no SysAdmin bypass for this policy.

---

## 4. Data scoping (backoffice views)

This is not a PDP policy but a data-filtering rule applied at the controller level (`CredentialProcedureController`), using the same SysAdmin definition.

| User type | Visible procedures |
|---|---|
| SysAdmin | All procedures from all organizations |
| Regular user | Only procedures belonging to their `organizationIdentifier` |

---

## Policy rules inventory

| Rule class | What it checks | SysAdmin bypass | Used in |
|---|---|---|---|
| `RequirePowerRule` | User has a specific power (function + action) with a domain matching the tenant | Yes | Backoffice, StatusList |
| `RequireOrganizationRule` | User's organization matches the resource's organization | Yes | Backoffice, StatusList |
| `RequireSignerIssuanceRule` | User is SysAdmin with `Onboarding / Execute` | No (sysAdmin IS the rule) | Issuance Employee, Machine |
| `RequireMandatorEmployeeIssuanceRule` | Mandator org match + powers limited to `ProductOffering` | No | Issuance Employee |
| `RequireMandatorMachineIssuanceRule` | Mandator org match + powers limited to `Onboarding` | No | Issuance Machine |
| `RequireCertificationIssuanceRule` | Signer + idToken both have `Certification / Attest` | No | Issuance LabelCredential |