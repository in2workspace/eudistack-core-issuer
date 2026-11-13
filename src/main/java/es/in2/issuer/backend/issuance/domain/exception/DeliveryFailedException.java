package es.in2.issuer.backend.issuance.domain.exception;

import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;

import java.io.Serial;

/**
 * The delivery flow of a valid request could not be completed (EUD-254 FR-03, AC-03). It carries a
 * closed {@link DeliveryErrorCode}, never the cause's message: a failure of the signing service, the
 * status list or the database can name internal URLs or the tenant's schema. The cause is kept for the
 * log, and so that a retry signal it carries (a signing configuration change) is still found.
 */
public class DeliveryFailedException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final DeliveryErrorCode code;

    public DeliveryFailedException(DeliveryErrorCode code, Throwable cause) {
        super("Delivery failed: " + code.value(), cause);
        this.code = code;
    }

    public DeliveryErrorCode code() {
        return code;
    }
}
