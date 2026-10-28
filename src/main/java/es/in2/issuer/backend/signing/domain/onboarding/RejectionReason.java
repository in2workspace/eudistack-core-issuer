package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;

/**
 * Why an onboarding event is not a success. The names are the reasons of the audit catalogue for
 * {@code SigningConfigurationChanged} (EUD-244) and each one belongs to the result the catalogue gives it: a
 * rejection by a validation is {@code Denied}, a failure of KMS or of the database is {@code Failure}. No reason
 * outside the catalogue vocabulary may be added without a new version of the catalogue.
 */
public enum RejectionReason {
    POLICY_DENIED("PolicyDenied", Result.DENIED),
    INVALID_KEY("InvalidKey", Result.DENIED),
    INVALID_CERTIFICATE("InvalidCertificate", Result.DENIED),
    KEY_IN_USE("KeyInUse", Result.DENIED),
    /** The only {@code Failure} reason of the catalogue: KMS or the database could not do what was asked. */
    PROVIDER_UNAVAILABLE("ProviderUnavailable", Result.FAILURE);

    private final String catalogName;
    private final Result result;

    RejectionReason(String catalogName, Result result) {
        this.catalogName = catalogName;
        this.result = result;
    }

    public String catalogName() {
        return catalogName;
    }

    /** The result of an event that carries this reason. */
    public Result result() {
        return result;
    }
}
