package es.in2.issuer.backend.signing.infrastructure.qtsp.auth;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import reactor.core.publisher.Mono;

public interface QtspAuthService {

    Mono<String> requestAccessToken(SigningRequest signingRequest, String scope, boolean includeAuthorizationDetails);
}
