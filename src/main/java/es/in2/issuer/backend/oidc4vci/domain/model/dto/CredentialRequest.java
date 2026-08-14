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
@Builder
public record CredentialRequest(
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @JsonProperty(value = "format") String format,
        @JsonProperty(value = "proof") Proof proof,
        @JsonProperty(value = "proofs") Proofs proofs) {
}
