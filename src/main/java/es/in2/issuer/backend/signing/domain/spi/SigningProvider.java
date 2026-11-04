package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import reactor.core.publisher.Mono;

/** Signs for one signing modality; there is exactly one provider per {@link SigningModality}. */
public interface SigningProvider {

    SigningModality modality();

    Mono<SigningResult> sign(SigningRequest request);
}
