package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import reactor.core.publisher.Mono;

public interface SignDocService {
    Mono<SigningResult> signIssuedCredential(SigningRequest signingRequest, String issuanceId);
    Mono<SigningResult> signSystemCredential(SigningRequest signingRequest);
}
