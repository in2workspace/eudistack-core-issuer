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
 * <p>Unlike the regular issuance endpoint, bootstrap is an administrative
 * flow called by devops/CI scripts. The destination tenant is therefore
 * declared explicitly in the payload — not derived from hostname or
 * {@code X-Tenant-Domain} header, which are meaningless for an out-of-band
 * admin caller.
 */
@Builder
public record BootstrapRequest(
        @NotBlank(message = "tenant is required")
        @JsonProperty(value = "tenant", required = true) String tenant,
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
     * consumed by the issuance workflow. The {@code tenant} field is dropped
     * because it is not part of the issuance domain model — it controls the
     * persistence schema, which is applied via Reactor context.
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
