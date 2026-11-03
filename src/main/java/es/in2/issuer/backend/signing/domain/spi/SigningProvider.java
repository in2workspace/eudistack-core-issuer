package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import reactor.core.publisher.Mono;

import java.util.List;

/** Signs for one signing modality; there is exactly one provider per {@link SigningModality}. */
public interface SigningProvider {

    SigningModality modality();

    /**
     * The certificate chain the signature will carry in its {@code x5c} header (base64 DER, leaf first, root
     * excluded), when it is known before signing, without calling the network. Empty when only the signing itself
     * learns it, as with a QTSP.
     */
    Mono<List<String>> resolveChain(ActiveSigningConfig config);

    Mono<SigningResult> sign(SigningRequest request);
}
