package es.in2.issuer.backend.dome.domain.model.sync;

import es.in2.issuer.backend.shared.validation.ValidUuidV7;
import java.util.UUID;

/**
 * Value object representing a unique identifier for a synchronization request.ç
 * Used to ensure operations are idempotent (can be repeated without unintended side effects)
 *
 * @param value The UUID (version 7) acting as the unique transaction ticket for the request.
 */
public record IdempotencyKey (
        @ValidUuidV7
        UUID value
) {}
