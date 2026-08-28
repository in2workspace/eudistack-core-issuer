package es.in2.issuer.backend.oidc4vci.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

// OID4VCI 1.0 Final §8.2 "proofs" (plural) form of the Credential Request,
// mapping a proof type to a non-empty array of proofs of that type.
@Builder
public record Proofs(
        @JsonProperty(value = "jwt") List<String> jwt) {
}
