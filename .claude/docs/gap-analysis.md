# Gap Analysis: Current State vs OID4VCI 1.0 Final

## Reference

- **Target spec**: OID4VCI 1.0 Final + HAIP 1.0 + ARF 2.8
- **Reference implementation**: fikua-lab (`/Users/ocanades/Projects/fikua/fikua-lab`)
- **Current implementation**: altia-eudistack-issuer-core-backend

## Feature Matrix

### Grant Types

| Feature | OID4VCI 1.0 | fikua-lab | altia-issuer | Gap |
|---------|-------------|-----------|-------------|-----|
| `pre-authorized_code` (sin OTP) | Required | Done | Done | None |
| `pre-authorized_code` + `tx_code` (OTP) | Required | Done | Done | None |
| `authorization_code` | Required | Done (full HAIP) | **Missing** | **Total** |
| `refresh_token` | Optional | Not impl | Done | Ahead |

### Authorization Code Flow Components

| Component | Spec | fikua-lab | altia-issuer | Gap |
|-----------|------|-----------|-------------|-----|
| PAR endpoint (`POST /par`) | RFC 9126 | Done | **Missing** | **Total** |
| Authorization endpoint (`GET /authorize`) | OID4VCI 1.0 §5 | Done | **Missing** | **Total** |
| PKCE S256 | RFC 7636 | Done | **Missing** | **Total** |
| `issuer_state` in Credential Offer | OID4VCI 1.0 §4.1.1 | Done | **Missing** | **Total** |
| `iss` in authorization response | RFC 9207 | Done | **Missing** | **Total** |
| Token endpoint (auth_code grant) | OID4VCI 1.0 §6 | Done | **Missing** | **Total** |

### HAIP Security

| Component | HAIP 1.0 | fikua-lab | altia-issuer | Gap |
|-----------|----------|-----------|-------------|-----|
| DPoP (RFC 9449) | Mandatory | Done | **Missing** | **Total** |
| Client Attestation (WIA) | Mandatory | Done | **Missing** | **Total** |
| Response encryption (ECDH-ES) | Optional | Partially done | **Missing** | **Total** |

### Credential Formats

| Format | OID4VCI 1.0 | fikua-lab | altia-issuer | Gap |
|--------|-------------|-----------|-------------|-----|
| `jwt_vc_json` (W3C VCDM v2.0) | Supported | Supported | **Done** | None |
| `dc+sd-jwt` (SD-JWT VC) | Primary for EUDI | Done (primary) | **Missing** | **Total** |
| `mso_mdoc` (ISO 18013-5) | Supported | Done | Placeholder only | **Partial** |

### Metadata

| Component | OID4VCI 1.0 Final | fikua-lab | altia-issuer | Gap |
|-----------|-------------------|-----------|-------------|-----|
| `credential_configurations_supported` | Required | Done | Done (partial) | See below |
| `credential_metadata.claims[].path[]` | 1.0 Final format | Done | **Uses draft format** (`credential_definition.type[]`) | **Significant** |
| `nonce_endpoint` | Required | Done | **Missing** | **Significant** |
| `authorization_endpoint` in AS metadata | Required for auth_code | Done | **Missing** | **Total** |
| `pushed_authorization_request_endpoint` | Required for HAIP | Done | **Missing** | **Total** |
| `dpop_signing_alg_values_supported` | Required for HAIP | Done | **Missing** | **Total** |
| `code_challenge_methods_supported` | Required for auth_code | Done | **Missing** | **Total** |
| `token_endpoint_auth_methods_supported` | Required for HAIP | Done | **Missing** | **Total** |

### Issuance Flows

| Flow | OID4VCI 1.0 | fikua-lab | altia-issuer | Gap |
|------|-------------|-----------|-------------|-----|
| Issuer-Initiated (pre-auth) | Done | Done | **Done** | None |
| Issuer-Initiated (auth_code + issuer_state) | Done | Done | **Missing** | **Total** |
| Wallet-Initiated (no issuer_state) | Optional | Done | **Missing** | **Total** |
| By-reference offer (`credential_offer_uri`) | Required | Done | Done (via CredentialOfferCacheRepository) | None |
| Email delivery of offer | Optional | Done (Resend/NoOp) | Done (Spring Mail) | None |

### Credential Endpoint

| Feature | OID4VCI 1.0 Final | fikua-lab | altia-issuer | Gap |
|---------|-------------------|-----------|-------------|-----|
| `proofs` (plural, 1.0 Final) | Primary | Done | **Missing** (uses `proof` singular) | **Significant** |
| `proof` (singular, draft compat) | Backwards compat | Supported both | Done (singular only) | Acceptable |
| Format negotiation (sd-jwt vs jwt_vc) | Required | Done | **Missing** | **Total** |
| Nonce in proof JWT | Required | Done | Stubbed (TODO comment) | **Significant** |
| Notification endpoint | Required | Done | Done | None |
| Deferred credential | Optional | Not impl | Done | Ahead |

### Infrastructure

| Component | fikua-lab | altia-issuer | Gap |
|-----------|-----------|-------------|-----|
| Own Nonce Store | In-memory (NonceStore port) | Delegated to Keycloak (not used) | **Total** |
| Own Token Generation | Custom JWT with signing key | Custom JWT with signing key | None |
| Credential definitions | Metadata-driven from config | Hardcoded in Java Factories | **Significant** |
| Authentication | X.509 certificates (no Keycloak) | Keycloak (backoffice) + Verifier (OID4VCI) | **Needs migration** |

## Complexity Assessment Per Gap

| Gap | Complexity | New Files | Modified Files | Risk |
|-----|------------|-----------|----------------|------|
| Eliminate Keycloak | Medium | 0 | ~8 | Medium |
| Restructure PDP policies | Medium | ~6 | ~8 | Low (refactoring) |
| JSON Schema credentials | Medium-High | ~8-10 | ~12-15 | Low |
| SD-JWT format | High | ~6-8 | ~5-8 | Low (additive) |
| Authorization Code Flow + Issuer-Initiated | Very High | ~15-20 | ~10-12 | Medium |
| DPoP + PKCE + WIA | High | ~6-8 | ~5-6 | Medium |
| Updated metadata | Medium | ~2-3 | ~4-5 | Low |
| Own Nonce Store | Low | ~3 | ~2 | Low |
| Plural `proofs` support | Low | ~1 | ~2 | Low |

## Retrocompatibility Requirements

| Existing Feature | Strategy |
|-----------------|----------|
| W3C VCDM v2.0 (`jwt_vc_json`) | Keep as-is. SD-JWT is additional format, not replacement |
| Pre-authorized_code flow | Not touched. Token endpoint routes by `grant_type` |
| Pre-authorized_code + OTP | Not touched. PIN validation stays in current path |
| LEARCredentialEmployee/Machine/Label | Migrate to JSON Schema but output identical JSON. Byte-for-byte regression test |
| Credential Offer (pre-auth) | Extended to support `grants.authorization_code` alongside `grants.pre-authorized_code` |
| Metadata endpoints | Extended with new fields. Existing fields unchanged |
| Signing SPI | Not touched. Signs bytes regardless of payload format |
| Database schema | Additive only (new tables/columns). No modifications to existing |
| `proof` (singular) in credential request | Keep supporting. Add `proofs` (plural) support alongside |
