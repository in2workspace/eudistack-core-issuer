package es.in2.issuer.backend.statuslist.application.policies;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import reactor.core.publisher.Mono;

public interface StatusListPdpService {

    Mono<Void> validateRevokeCredential(String processId, String token, Issuance issuance);
    Mono<Void> validateRevokeCredentialSystem(String processId, Issuance issuance);
}

