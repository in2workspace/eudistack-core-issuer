package es.in2.issuer.backend.signing.domain.model;

/**
 * Why a signing operation failed. Names follow EUD-289 notas-tecnicas §4.
 *
 * <p>Provisional: the final contract (and whether this enum is the carrier) is decided
 * in phase B (decision D-7).
 */
public enum SigningFailureReason {
    NO_CONFIGURATION,
    KEY_UNUSABLE,
    UNSUPPORTED_ALGORITHM,
    CERTIFICATE_INVALID,
    INVALID_RESPONSE,
    SERVICE_UNAVAILABLE,
    OTHER
}
