package es.in2.issuer.backend.signing.domain.model.dto;

import jakarta.validation.constraints.NotBlank;

public record RemoteSignatureDto(
        @NotBlank String type,
        @NotBlank String url,
        @NotBlank String signPath,
        @NotBlank String clientId,
        @NotBlank String clientSecret,
        @NotBlank String credentialId,
        @NotBlank String credentialPassword,
        String certificateInfoCacheTtl
) {}