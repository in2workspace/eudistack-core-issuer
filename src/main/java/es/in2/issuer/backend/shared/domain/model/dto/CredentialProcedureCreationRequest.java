package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

import java.sql.Timestamp;

@Builder
public record CredentialProcedureCreationRequest(
        String procedureId,
        String organizationIdentifier,
        String credentialDecoded,
        String credentialType,
        String subject,
        Timestamp validUntil,
        String operationMode,
        String signatureMode,
        String email
        )
{
}
