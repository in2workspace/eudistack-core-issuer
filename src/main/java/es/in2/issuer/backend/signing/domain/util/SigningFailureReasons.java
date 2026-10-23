package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;

import java.util.HashSet;
import java.util.Set;

/**
 * Extracts the {@link SigningFailureReason} of a failure. Callers often re-wrap signing errors
 * (for example into {@code RemoteSignatureException}), so the cause chain is walked.
 */
public final class SigningFailureReasons {

    private SigningFailureReasons() {}

    /**
     * Returns the first reason other than {@code OTHER} carried by a {@link SigningException}
     * in the cause chain, or {@code OTHER} when there is none. A generic wrapper
     * ({@code OTHER}) therefore does not hide a classified cause.
     */
    public static SigningFailureReason of(Throwable throwable) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            if (current instanceof SigningException ex && ex.getReason() != SigningFailureReason.OTHER) {
                return ex.getReason();
            }
            current = current.getCause();
        }
        return SigningFailureReason.OTHER;
    }
}
