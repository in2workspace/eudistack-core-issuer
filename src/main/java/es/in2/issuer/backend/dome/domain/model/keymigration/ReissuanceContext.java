package es.in2.issuer.backend.dome.domain.model.keymigration;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record ReissuanceContext(
        UUID sourceIssuanceId,
        String holderCnfJwk,
        Instant originalValidFrom,
        Instant originalValidUntil
) {

    public ReissuanceContext {
        Objects.requireNonNull(sourceIssuanceId, "sourceIssuanceId must not be null");
        Objects.requireNonNull(holderCnfJwk, "holderCnfJwk must not be null");
    }
}

