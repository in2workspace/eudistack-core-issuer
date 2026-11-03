package es.in2.issuer.backend.shared.domain.policy.service;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import reactor.core.publisher.Mono;

public interface StatusListPdpService {

    Mono<Void> validateRevokeCredential(String processId, String token, Issuance issuance);
    Mono<Void> validateRevokeCredentialSystem(String processId, Issuance issuance);

    /**
     * Decides whether the caller may revoke at all, for a process that does not exist: the same
     * answer as for one that does, so a caller without the power cannot learn which ids exist.
     */
    Mono<Void> validateRevokePermission(String processId, String token);

    /**
     * Decides the caller's permission and scope on a process, regardless of its status. A process
     * outside the caller's scope fails as {@code IssuanceNotFoundException}: the answer is the same
     * as for one that does not exist (EUD-247 §5).
     */
    Mono<Void> validateRevokeScope(String processId, String token, Issuance issuance);
}
