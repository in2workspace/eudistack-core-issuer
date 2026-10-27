package es.in2.issuer.backend.signing.domain.util;

/**
 * Log-safe form of a KMS key reference. An ARN keeps only its resource part ({@code key/<id>} or
 * {@code alias/<name>}), enough to correlate with CloudTrail without writing the AWS account and region to
 * application logs. The results of a command and the state file keep the full ARN: the operator needs it.
 */
public final class KeyRefs {

    private static final int ARN_RESOURCE_FIELD = 5;

    private KeyRefs() {}

    public static String forLog(String keyRef) {
        if (keyRef == null || keyRef.isBlank()) {
            return "n/a";
        }
        if (!keyRef.startsWith("arn:")) {
            return keyRef;
        }
        // arn:partition:service:region:account:resource
        String[] fields = keyRef.split(":", ARN_RESOURCE_FIELD + 1);
        return fields.length > ARN_RESOURCE_FIELD && !fields[ARN_RESOURCE_FIELD].isBlank()
                ? fields[ARN_RESOURCE_FIELD]
                : "n/a";
    }
}
