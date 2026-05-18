package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import reactor.core.publisher.Mono;

public interface DelegatingSigningProvider {
    Mono<SigningResult> sign(SigningRequest request);
}
