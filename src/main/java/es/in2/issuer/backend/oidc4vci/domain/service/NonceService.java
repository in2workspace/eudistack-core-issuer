package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import reactor.core.publisher.Mono;

public interface NonceService {
    Mono<NonceResponse> issueNonce();
}
