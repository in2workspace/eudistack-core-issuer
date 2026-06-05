package es.in2.issuer.backend.dome.domain.model.sync;

/**
 * Composite key used for caching the results of the synchronization request.
 * Combines the tenant, the specific request ID, and the user's thumbprint to
 * prevent cache collisions across different users environments.
 *
 * @param tenant              The identifier of the current environment/tenant.
 * @param idempotencyKey      The unique ticket identifier of the current sync request.
 * @param holderKeyThumbprint The secure, unique identifier of the user's wallet.
 */
public record IdempotencyCacheKey (
        String tenant,
        IdempotencyKey idempotencyKey,
        HolderKeyThumbprint holderKeyThumbprint
) {}
