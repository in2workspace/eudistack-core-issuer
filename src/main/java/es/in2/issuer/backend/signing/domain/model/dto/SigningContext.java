package es.in2.issuer.backend.signing.domain.model.dto;

import lombok.Builder;

@Builder
public record SigningContext(
        String token,
        String issuanceId,
        String email
) {}