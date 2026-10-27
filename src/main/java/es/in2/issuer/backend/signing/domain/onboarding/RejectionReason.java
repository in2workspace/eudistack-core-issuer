package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * Why an onboarding is rejected. The names are the reasons of the audit catalogue for
 * {@code SigningConfigurationChanged} (EUD-244) that a rejection can carry.
 */
public enum RejectionReason {
    POLICY_DENIED("PolicyDenied"),
    INVALID_KEY("InvalidKey"),
    INVALID_CERTIFICATE("InvalidCertificate"),
    KEY_IN_USE("KeyInUse");

    private final String catalogName;

    RejectionReason(String catalogName) {
        this.catalogName = catalogName;
    }

    public String catalogName() {
        return catalogName;
    }
}
