package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import reactor.core.publisher.Mono;

public interface QtspAuthPort {

    Mono<String> requestAccessToken(SigningRequest signingRequest, String scope);

    Mono<String> requestAccessToken(SigningRequest signingRequest, String scope, boolean includeAuthorizationDetails);

}
