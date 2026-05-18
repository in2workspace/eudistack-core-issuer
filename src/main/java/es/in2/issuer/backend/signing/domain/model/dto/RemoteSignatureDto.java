package es.in2.issuer.backend.signing.domain.model.dto;

import jakarta.validation.constraints.NotBlank;

public record RemoteSignatureDto(
        @NotBlank String provider,
        @NotBlank String cscApiVersion,
        @NotBlank String url,
        @NotBlank String signingOperation,
        @NotBlank String credentialId,
        @NotBlank String credentialPassword,
        String certificateInfoCacheTtl,
        // OAuth2
        String clientId,
        String clientSecret,
        // Vintegris TrustedApp auth fields
        String applicationName,
        String qtspTenantId,
        String appId,
        String accessKey,
        String managerId
) {}
