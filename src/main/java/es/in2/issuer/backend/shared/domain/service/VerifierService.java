package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.OpenIDProviderMetadata;
import reactor.core.publisher.Mono;

public interface VerifierService {

    /**
     * Validates signature and expiration of a token previously matched to
     * this verifier by the caller. The {@code iss} claim is NOT validated
     * here; callers are expected to do exact-match validation via
     * {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}
     * before invoking this method.
     */
    Mono<Void> verifyToken(String accessToken);

    /**
     * Like {@link #verifyToken(String)} but skipping expiration check.
     * Used for out-of-band flows where the expiration check does not apply.
     */
    Mono<Void> verifyTokenWithoutExpiration(String accessToken);

    Mono<OpenIDProviderMetadata> getWellKnownInfo();
}
