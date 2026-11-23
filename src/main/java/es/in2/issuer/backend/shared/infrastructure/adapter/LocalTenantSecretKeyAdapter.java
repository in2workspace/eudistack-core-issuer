package es.in2.issuer.backend.shared.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * {@link TenantSecretKeyPort} of the {@code local} profile only (§6 of the EUD-254 design): there is no Parameter
 * Store in the local stack, so the key of each tenant is derived (HMAC-SHA256) from a seed set in a property. Every
 * tenant, also one created later, has its own key, the same on every restart. It never runs outside that profile.
 */
public class LocalTenantSecretKeyAdapter implements TenantSecretKeyPort {

    private static final String LABEL = "eudistack-local-tenant-secret-key|";
    private static final int MIN_SEED_CHARS = 32;

    private final byte[] seed;

    public LocalTenantSecretKeyAdapter(String seed) {
        if (seed == null || seed.strip().length() < MIN_SEED_CHARS) {
            throw new IllegalStateException("issuer.search-identifiers.local-key-seed needs at least "
                    + MIN_SEED_CHARS + " characters with the local profile");
        }
        this.seed = seed.strip().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public Mono<byte[]> keyOf(String tenant) {
        return Mono.fromCallable(() -> {
            if (tenant == null || tenant.isBlank()) {
                throw new TenantSecretKeyUnavailableException("Not a tenant whose secret key can be read");
            }
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(seed, "HmacSHA256"));
                return mac.doFinal((LABEL + tenant).getBytes(StandardCharsets.UTF_8));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("HMAC-SHA256 is not available", e);
            }
        });
    }
}
