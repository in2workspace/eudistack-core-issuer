package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Completion;
import reactor.core.publisher.Mono;

/**
 * Reports that an attestation was signed and delivered. The report joins the transaction that is already
 * active, so it commits or rolls back with the write that marks the attestation as delivered.
 */
public interface IssuanceCompletionAuditPort {

    Mono<Void> recordCompletion(String issuanceId, Completion completion, String signedCredential);
}
