package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.infrastructure.model.CscSignType;
import reactor.core.publisher.Mono;

public interface SigningProvider {
    CscSignType supportedProvider();

    Mono<SigningResult> sign(SigningRequest request);
}
