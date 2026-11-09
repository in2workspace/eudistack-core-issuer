package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record IssuanceRequest(
        @NotBlank(message = "credential_configuration_id is required")
        @Size(max = 100, message = "credential_configuration_id must be at most 100 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._-]*$", message = "credential_configuration_id must only contain letters, digits, dots, underscores and hyphens")
        @JsonAlias("schema")
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @NotNull(message = "payload is required")
        @JsonProperty(value = "payload", required = true) JsonNode payload,
        // EUD-254: exactly one of email, ui or direct (email when absent). Any other value -- a list of
        // modes included -- is invalid_delivery_mode, not a BAD_REQUEST on its shape: the workflow checks
        // it, and the value sent never reaches a log line or a metric tag.
        @JsonProperty("delivery") String delivery,
        @NotBlank(message = "email is required")
        @Email(message = "email must be a well-formed email address")
        @Size(max = 254, message = "email must be at most 254 characters")
        @JsonProperty("email") String email,
        // EUD-254: any value other than its two is invalid_grant_type, not a BAD_REQUEST on its shape --
        // OfferGrantType checks it, and the value sent is never logged or echoed back.
        @JsonProperty("grant_type") String grantType,
        @JsonProperty("holder_key") JsonNode holderKey,
        // EUD-253 FR-07 / EUD-268: organization the attestation is issued for. Optional: absent, it is
        // the caller's own; another organization of the tenant is only accepted from a tenant
        // administrator (action E2). The attestation content never sets it.
        @Size(max = 100, message = "organization must be at most 100 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._:-]*$", message = "organization must only contain letters, digits, dots, underscores, colons and hyphens")
        @JsonProperty("organization") String organization
) {
    public IssuanceRequest(String credentialConfigurationId, JsonNode payload, String delivery,
                           String email, String grantType) {
        this(credentialConfigurationId, payload, delivery, email, grantType, null, null);
    }

    public IssuanceRequest(String credentialConfigurationId, JsonNode payload, String delivery,
                           String email, String grantType, JsonNode holderKey) {
        this(credentialConfigurationId, payload, delivery, email, grantType, holderKey, null);
    }

    /** This request with the organization the authorization decided the process belongs to. */
    public IssuanceRequest withOrganization(String decidedOrganization) {
        return new IssuanceRequest(credentialConfigurationId, payload, delivery, email, grantType, holderKey,
                decidedOrganization);
    }

    public IssuanceRequest withPayload(JsonNode newPayload) {
        return new IssuanceRequest(credentialConfigurationId, newPayload, delivery, email, grantType, holderKey,
                organization);
    }
}
