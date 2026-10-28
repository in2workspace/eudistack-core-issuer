package es.in2.issuer.backend.signing.domain.util;

import java.util.regex.Pattern;

/**
 * Log-safe form of a KMS key reference. An ARN keeps only its resource part ({@code key/<id>} or
 * {@code alias/<name>}), enough to correlate with CloudTrail without writing the AWS account and region to
 * application logs. The results of a command and the state file keep the full ARN: the operator needs it.
 */
public final class KeyRefs {

    private static final int ARN_RESOURCE_FIELD = 5;
    /**
     * The full ARN of a KMS key, the only form a signing configuration stores (the CHECK of the tenant migration V15 has
     * the same expression): never a KeyId or an alias, because references are compared as text.
     */
    private static final Pattern KMS_KEY_ARN =
            Pattern.compile("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$");

    private KeyRefs() {}

    /** @return whether the reference is the full ARN of a KMS key */
    public static boolean isKeyArn(String keyRef) {
        return keyRef != null && KMS_KEY_ARN.matcher(keyRef).matches();
    }

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
