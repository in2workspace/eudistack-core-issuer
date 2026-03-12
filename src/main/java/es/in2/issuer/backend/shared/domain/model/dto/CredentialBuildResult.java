package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

import java.sql.Timestamp;

@Builder
public record CredentialBuildResult(
        String credentialDataSet,
        String subject,
        String organizationIdentifier,
        Timestamp validFrom,
        Timestamp validUntil
) {
}
