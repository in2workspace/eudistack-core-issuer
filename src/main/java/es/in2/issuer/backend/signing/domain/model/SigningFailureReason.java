package es.in2.issuer.backend.signing.domain.model;

/**
 * Why a signing operation failed. Names follow the EUD-251 design (§9.4). {@code OTHER} is the
 * fallback for failures that are not classified yet; the design's {@code CREDENTIALS_REJECTED}
 * is not here because nothing in the current signing paths produces it.
 */
public enum SigningFailureReason {
    NO_CONFIGURATION,
    KEY_UNUSABLE,
    UNSUPPORTED_ALGORITHM,
    CERTIFICATE_INVALID,
    INVALID_RESPONSE,
    PROVIDER_UNAVAILABLE,
    OTHER
}
