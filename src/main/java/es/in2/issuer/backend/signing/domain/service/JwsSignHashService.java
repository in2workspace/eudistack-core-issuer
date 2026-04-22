package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import reactor.core.publisher.Mono;

public interface JwsSignHashService {
    Mono<String> signJwtWithSignHash(RemoteSignatureDto cfg, String accessToken, String headerJson, String payloadJson, String signAlgoOid);
}
