package es.in2.issuer.backend.issuance.application.workflow.policies;

import reactor.core.publisher.Mono;

public interface IssuancePdpService {

    Mono<Void> validateSignCredential(String processId, String token, String issuanceId);
}
