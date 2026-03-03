package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationResponse;
import reactor.core.publisher.Mono;

public interface ParService {
    Mono<PushedAuthorizationResponse> processPar(
            PushedAuthorizationRequest request,
            String dpopHeader,
            String wiaHeader,
            String wiaPopHeader,
            String requestUri
    );
}
