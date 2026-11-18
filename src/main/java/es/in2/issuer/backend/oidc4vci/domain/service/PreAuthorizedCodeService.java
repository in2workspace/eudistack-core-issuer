package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import reactor.core.publisher.Mono;

public interface PreAuthorizedCodeService {
    Mono<PreAuthorizedCodeResponse> issuePreAuthorizedCode(String processId, Mono<String> issuanceIdMono);

    /** Withdraws a pre-authorized code so it can no longer be exchanged at the token endpoint. */
    Mono<Void> revokePreAuthorizedCode(String preAuthorizedCode);
}
