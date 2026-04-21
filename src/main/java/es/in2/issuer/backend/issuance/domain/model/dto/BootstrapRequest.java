package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

/**
 * Request body for the cross-tenant bootstrap endpoint.
 *
 * <p>The destination tenant is declared via the {@code X-Tenant-Id} HTTP
 * header (same convention as the rest of the API). It is NOT part of the
 * body. Validation and registry lookup are performed by
 * {@code TenantDomainWebFilter} before the controller is invoked.
 */
@Builder
public record BootstrapRequest(
        @NotBlank(message = "credential_configuration_id is required")
        @JsonAlias("schema")
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @NotNull(message = "payload is required")
        @JsonProperty(value = "payload", required = true) JsonNode payload,
        @JsonProperty("delivery") String delivery,
        @NotBlank(message = "email is required")
        @JsonProperty("email") String email,
        @JsonProperty("grant_type") String grantType
) {

    /**
     * Projects this bootstrap request onto the generic {@link IssuanceRequest}
     * consumed by the issuance workflow.
     */
    public IssuanceRequest toIssuanceRequest() {
        return IssuanceRequest.builder()
                .credentialConfigurationId(credentialConfigurationId)
                .payload(payload)
                .delivery(delivery)
                .email(email)
                .grantType(grantType)
                .build();
    }
}
