package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListPublicBaseUrlNotResolvableException;
import es.in2.issuer.backend.statuslist.domain.exception.TenantBindingMismatchException;
import es.in2.issuer.backend.statuslist.domain.exception.UnknownTenantException;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.Set;

/**
 * Single point of the retryable-vs-permanent policy for the revocation-instruction
 * listener (ES-01, ES-02, ES-04, ES-05). The listener (T14) uses this to decide whether
 * to let an exception propagate normally — retried by
 * {@link es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig}'s
 * interceptor, DLQ only after exhausting attempts — or wrap it as
 * {@code AmqpRejectAndDontRequeueException} for an immediate, zero-retry DLQ routing.
 * <p>
 * Default for an unclassified exception is <b>retryable</b>: cheap fast-backoff retries
 * (1s/2s/4s) either recover a genuinely transient failure or land the message in the DLQ
 * a few seconds later anyway, which is safer than guessing a bug is permanent.
 */
@Component
public class RevocationInstructionErrorClassifier {

    /**
     * Signing failures that another attempt cannot fix (EUD-251 design §9.4): only
     * {@code PROVIDER_UNAVAILABLE} and an unclassified {@code OTHER} stay retryable.
     */
    private static final Set<SigningFailureReason> PERMANENT_SIGNING_FAILURES = EnumSet.of(
            SigningFailureReason.NO_CONFIGURATION,
            SigningFailureReason.KEY_UNUSABLE,
            SigningFailureReason.UNSUPPORTED_ALGORITHM,
            SigningFailureReason.CERTIFICATE_INVALID,
            SigningFailureReason.INVALID_RESPONSE);

    public boolean isRetryable(Throwable error) {
        return !isPermanent(error);
    }

    private boolean isPermanent(Throwable error) {
        return error instanceof InvalidRevocationInstructionException // ES-01: malformed / missing fields
                || error instanceof UnknownTenantException // AC-07/EC-07: tenant not in tenant_registry
                || error instanceof TenantBindingMismatchException // AC-12: declared tenant != configured
                || error instanceof IssuanceNotFoundException // ES-02: credential does not exist
                || error instanceof StatusListIndexNotFoundException // no allocation for the issuance
                || error instanceof StatusListNotFoundException // list vanished from under an allocation
                || error instanceof StatusListPublicBaseUrlNotResolvableException // AD-2 fail-closed
                || PERMANENT_SIGNING_FAILURES.contains(SigningFailureReasons.of(error)); // reason anywhere in the cause chain
    }

    // Not part of the decision (default is already retryable) — documented here so the
    // known transient categories this Story anticipates (ES-04, ES-05, EC-03) are visible
    // to a reader without having to reconstruct them from the test matrix:
    // RemoteSignatureException / R2dbcException (ES-04, QTSP/DB unavailable),
    // OptimisticUpdateException (RC-2 residual after internal retries),
    // RevocationInstructionInProgressException (EC-03, overlapping redelivery),
    // TimeoutException (ES-05, processing exceeded the bounded block()).
}
