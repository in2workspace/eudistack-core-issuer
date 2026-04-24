package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.OpenIDProviderMetadata;
import reactor.core.publisher.Mono;

public interface VerifierService {

    Mono<Void> verifyToken(String accessToken);
    Mono<Void> verifyTokenWithoutExpiration(String accessToken);

    /**
     * Verifies the token skipping the issuer-URL match against APP_VERIFIER_URL.
     * Used when the caller has already matched {@code iss} exactly against the
     * expected verifier base URL (derived from the request origin under
     * same-origin routing). Signature and expiration are still validated.
     */
    Mono<Void> verifyTokenSkippingIssuerCheck(String accessToken);

    Mono<OpenIDProviderMetadata> getWellKnownInfo();
}
