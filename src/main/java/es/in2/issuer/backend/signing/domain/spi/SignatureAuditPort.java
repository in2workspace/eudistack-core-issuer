package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignedObject;
import reactor.core.publisher.Mono;

/** Reports a signing attempt, without changing its outcome: the signature, or the error, goes through. */
public interface SignatureAuditPort {

    /**
     * @param resource the object the signature is for, {@code <kind>:<id>}
     * @param signing  the signing attempt; it emits the signed value
     */
    Mono<String> recordAttempt(String resource, SignedObject signedObject, Mono<String> signing);
}
