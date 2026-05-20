package es.in2.issuer.backend.dome.domain.model.sync;

public record IdempotencyCacheKey (
        String tenant,
        IdempotencyKey idempotencyKey,
        HolderKeyThumbprint holderKeyThumbprint
) {}
