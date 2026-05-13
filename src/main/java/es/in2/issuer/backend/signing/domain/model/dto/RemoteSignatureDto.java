package es.in2.issuer.backend.signing.domain.model.dto;

import jakarta.validation.constraints.NotBlank;

public record RemoteSignatureDto(
        @NotBlank String url,
        String clientId,
        String clientSecret,
        @NotBlank String credentialId,
        @NotBlank String credentialPassword,
        String certificateInfoCacheTtl,
        @NotBlank String signingOperation,
        // Vintegris TrustedApp auth fields
        String applicationName,
        String qtspTenantId,
        String appId,
        String accessKey,
        String managerId
) {}
