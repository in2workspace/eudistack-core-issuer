package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.signing.domain.model.CertificateCheck;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * An own-key certificate failed one of its checks; {@link #getCheck()} says which one, for the audit trail.
 * The reason is {@code CERTIFICATE_INVALID} unless the caller classifies it otherwise.
 */
public class CertificateCheckException extends SigningException {

    private final CertificateCheck check;

    public CertificateCheckException(CertificateCheck check, String message) {
        this(SigningFailureReason.CERTIFICATE_INVALID, check, message, null);
    }

    public CertificateCheckException(CertificateCheck check, String message, Throwable cause) {
        this(SigningFailureReason.CERTIFICATE_INVALID, check, message, cause);
    }

    public CertificateCheckException(SigningFailureReason reason, CertificateCheck check, String message,
                                     Throwable cause) {
        super(reason, message, cause);
        this.check = check;
    }

    public CertificateCheck getCheck() {
        return check;
    }

    /** The failed check of the first {@link CertificateCheckException} in the cause chain, if any. */
    public static Optional<CertificateCheck> of(Throwable throwable) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            if (current instanceof CertificateCheckException ex) {
                return Optional.of(ex.getCheck());
            }
            current = current.getCause();
        }
        return Optional.empty();
    }
}
