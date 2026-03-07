package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

import java.sql.Timestamp;

@Builder
public record IssuanceCreationRequest(
        String issuanceId,
        String organizationIdentifier,
        String credentialDataSet,
        String credentialType,
        String credentialFormat,
        String subject,
        Timestamp validUntil,
        String email,
        String delivery
) {
}
