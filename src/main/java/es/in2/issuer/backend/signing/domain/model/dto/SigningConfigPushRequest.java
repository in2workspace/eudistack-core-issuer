package es.in2.issuer.backend.signing.domain.model.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SigningConfigPushRequest(
        @NotBlank String provider,
        @NotNull @Valid RemoteSignatureDto remoteSignature
) {}
