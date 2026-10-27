package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.util.KeyRefs;

/**
 * Log-safe form of a KMS key reference, for the Issuer's KMS logs. The implementation is shared with the
 * onboarding tool: see {@link KeyRefs}.
 */
public final class KmsKeyRefs {

    private KmsKeyRefs() {}

    public static String forLog(String keyRef) {
        return KeyRefs.forLog(keyRef);
    }
}
