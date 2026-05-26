package es.in2.issuer.backend.dome.infrastructure.adapter.web.dto;

import es.in2.issuer.backend.shared.validation.HexString;
import es.in2.issuer.backend.shared.validation.ValidUuidV7;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/**
 * Request DTO for the sync-credentials endpoint
 */
public record SyncCredentialsRequest(
        @NotNull(message = "idempotencyKey cannot be null")
        @ValidUuidV7
        UUID idempotencyKey,

        @NotNull(message = "holderKeyThumbprint cannot be null")
        @HexString(length = 64)
        String holderKeyThumbprint
) {}
