package es.in2.issuer.backend.signing.domain.spi;

import reactor.core.publisher.Mono;

public interface QtspSignHashPort {

    Mono<String> authorizeForHash(String accessToken, String hashB64Url, String hashAlgoOid);

    Mono<String> signHash(String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid);

}
