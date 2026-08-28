package es.in2.issuer.backend.oidc4vci.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.dto.Proof;
import lombok.Builder;

// OID4VCI 1.0 Final §8.2: with credential_configuration_id, format is implied by the
// referenced metadata entry and is no longer a required (or even meaningful) top-level
// request parameter - kept here as optional only for clients that still send it.
// "proofs" (plural, batch-capable) is the Final form; "proof" (singular) is kept
// alongside it for backward compatibility with clients - e.g. our own Wallet PWA -
// that have not yet migrated off the earlier draft shape.
//
// credential_configuration_id and credential_identifier are mutually exclusive addressing
// modes per §8.2: credential_identifier is used only when the Token Response returned
// authorization_details with credential_identifiers, which this Issuer never does (only the
// scope-based flow is implemented) - so credential_identifier is recognized here solely to
// reject it cleanly (Oid4VciCredentialWorkflowImpl -> unknown_credential_identifier) instead
// of failing JSON deserialization when a client sends it. Not marked required=true: with
// credential_identifier it MUST NOT be present at all.
@Builder
public record CredentialRequest(
        @JsonProperty(value = "credential_configuration_id") String credentialConfigurationId,
        @JsonProperty(value = "credential_identifier") String credentialIdentifier,
        @JsonProperty(value = "format") String format,
        @JsonProperty(value = "proof") Proof proof,
        @JsonProperty(value = "proofs") Proofs proofs) {
}
