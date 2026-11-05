package es.in2.issuer.backend.signing.domain.model;

import java.util.Locale;

/**
 * The own-key certificate check that failed, recorded in the audit trail of the signing attempt
 * (EUD-251 FR-14). Local checks only: trust validation of the chain is EUD-264.
 */
public enum CertificateCheck {
    /** The PEM chain or a stored certificate cannot be parsed or encoded, or holds no certificate. */
    UNPARSABLE,
    NOT_YET_VALID,
    EXPIRED,
    NOT_P256,
    /** The leaf is a CA certificate: a CA does not sign content. */
    CA_CERTIFICATE,
    /** The key usage of the leaf allows neither digitalSignature nor nonRepudiation. */
    SIGNING_NOT_ALLOWED,
    /** A certificate is not issued by the next one, or an intermediate is not a valid CA. */
    CHAIN_INVALID,
    NO_ORGANIZATION_IDENTIFIER,
    /** The subject of the leaf holds more than one organizationIdentifier: which organization it is would be ambiguous. */
    DUPLICATED_ORGANIZATION_IDENTIFIER,
    /** The leaf belongs to another organization than the tenant's. */
    ORGANIZATION_MISMATCH,
    /** The serial number of the leaf, which names its KMS key, is zero or negative. */
    NON_POSITIVE_SERIAL_NUMBER;

    public String auditValue() {
        return name().toLowerCase(Locale.ROOT);
    }
}
