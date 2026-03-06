package es.in2.issuer.backend.shared.infrastructure.controller.error;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialErrorResponse(@JsonProperty("error") String error,
                                      @JsonProperty("description") String description) {
}
