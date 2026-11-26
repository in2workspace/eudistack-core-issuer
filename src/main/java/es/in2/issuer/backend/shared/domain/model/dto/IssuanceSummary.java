package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * An issuance process in the listing (EUD-255 contract, {@code IssuanceSummary}): its data without
 * the attestation, nor the grant, the offer refresh token, the delivery attempt, the version or the
 * search identifier hashes (FR-07). Null fields are left out, as everywhere in the application.
 *
 * @param updated the last change of the process: its creation or its last change of state (AD-2)
 * @param tenant  only from the platform tenant
 */
@Builder
public record IssuanceSummary(
        @JsonProperty("id") UUID id,
        @JsonProperty("organization_identifier") String organizationIdentifier,
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("credential_format") String credentialFormat,
        @JsonProperty("life_cycle_status") String lifeCycleStatus,
        @JsonProperty("subject") String subject,
        @JsonProperty("email") String email,
        @JsonProperty("delivery") String delivery,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
        @JsonProperty("valid_from") Instant validFrom,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
        @JsonProperty("valid_until") Instant validUntil,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
        @JsonProperty("created") Instant created,
        @JsonProperty("created_by") String createdBy,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
        @JsonProperty("updated") Instant updated,
        @JsonProperty("tenant") String tenant
) {
}
