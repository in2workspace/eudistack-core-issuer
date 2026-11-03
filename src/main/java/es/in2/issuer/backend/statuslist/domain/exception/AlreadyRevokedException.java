package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * The attestation is already revoked. A client that retries after losing the response learns
 * from it that the revocation was applied, and no effect is repeated (EUD-247 §5).
 */
public class AlreadyRevokedException extends RuntimeException {

    public AlreadyRevokedException(String issuanceId) {
        super("Attestation already revoked; issuanceId: " + issuanceId);
    }
}
