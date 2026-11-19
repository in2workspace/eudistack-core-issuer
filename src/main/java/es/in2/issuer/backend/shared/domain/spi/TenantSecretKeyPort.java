package es.in2.issuer.backend.shared.domain.spi;

import reactor.core.publisher.Mono;

/**
 * The secret key of a tenant (EUD-267; AD-3 of the EUD-254 design): 32 random bytes per tenant, kept outside the
 * database, with which the fingerprints of the search identifiers and the recipient pseudonyms are computed. In AWS
 * it is a {@code SecureString} of Parameter Store; in the local stack, a key derived from a local seed.
 */
public interface TenantSecretKeyPort {

    /**
     * The key of the tenant.
     *
     * @throws es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException (as the error of
     *         the {@code Mono}) when the key is not configured or cannot be read
     */
    Mono<byte[]> keyOf(String tenant);

    /**
     * The key of the tenant read again from its source, skipping any cached copy, which is then replaced. Used when
     * there are signs the key was rotated since it was read (another instance indexed with another key). By default,
     * {@link #keyOf}: a source without cache is always current.
     */
    default Mono<byte[]> refreshedKeyOf(String tenant) {
        return keyOf(tenant);
    }
}
