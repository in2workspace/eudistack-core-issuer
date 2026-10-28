package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingUsageException;

import java.net.URI;

/**
 * Connection settings of one run of the onboarding tool. The names of the environment variables are the
 * Issuer's, so the same task definition can supply them.
 *
 * @param dbUrl               JDBC URL ({@code SPRING_FLYWAY_URL})
 * @param dbUser              database user ({@code SPRING_R2DBC_USERNAME})
 * @param dbPassword          database password ({@code SPRING_R2DBC_PASSWORD}); only from the environment, never an argument
 * @param kmsRegion           AWS region ({@code ISSUER_SIGNING_KMS_REGION}, then {@code AWS_REGION}); {@code null} lets the SDK resolve it
 * @param kmsEndpoint         endpoint override for emulators such as LocalStack ({@code ISSUER_SIGNING_KMS_ENDPOINT}); applies to KMS and STS
 * @param deletionWindowDays  waiting period of {@code ScheduleKeyDeletion}, 7 to 30 days
 * @param keyPolicy           JSON key policy for the keys {@code prepare} creates ({@code --key-policy}); {@code null}
 *                            leaves the KMS default, which is only accepted with {@code --non-production}
 * @param auditSink           where the audit events go ({@code OWN_KEY_AUDIT_SINK}, {@code log} or {@code outbox})
 * @param production          the production checks apply (the default): the endpoint URLs the AWS SDK reads from its
 *                            configuration are ignored
 * @param expectedAwsAccount  the AWS account the credentials must belong to ({@code --expected-aws-account}); {@code null}
 *                            skips the check, which is only allowed with {@code --non-production}
 */
public record OnboardingSettings(
        String dbUrl,
        String dbUser,
        String dbPassword,
        String kmsRegion,
        URI kmsEndpoint,
        int deletionWindowDays,
        AuditSinkMode auditSink,
        String keyPolicy,
        boolean production,
        String expectedAwsAccount
) {

    /** For tests against an emulator: no production checks and no expected account. */
    public OnboardingSettings(String dbUrl, String dbUser, String dbPassword, String kmsRegion, URI kmsEndpoint,
                              int deletionWindowDays, AuditSinkMode auditSink) {
        this(dbUrl, dbUser, dbPassword, kmsRegion, kmsEndpoint, deletionWindowDays, auditSink, null, false, null);
    }

    /** Where the audit events go: the log (default) or the outbox of the EUD-244 starter, if the build has it. */
    public enum AuditSinkMode {
        LOG,
        OUTBOX
    }

    static final int MIN_DELETION_WINDOW_DAYS = 7;
    static final int MAX_DELETION_WINDOW_DAYS = 30;

    public OnboardingSettings {
        if (deletionWindowDays < MIN_DELETION_WINDOW_DAYS || deletionWindowDays > MAX_DELETION_WINDOW_DAYS) {
            throw new OnboardingUsageException("the deletion window must be between " + MIN_DELETION_WINDOW_DAYS
                    + " and " + MAX_DELETION_WINDOW_DAYS + " days");
        }
    }

    /** The password never appears in a printed value. */
    @Override
    public String toString() {
        return "OnboardingSettings[dbUrl=" + dbUrl + ", dbUser=" + dbUser + ", kmsRegion=" + kmsRegion
                + ", kmsEndpoint=" + kmsEndpoint + ", deletionWindowDays=" + deletionWindowDays + ", auditSink=" + auditSink + ", production=" + production
                + ", expectedAwsAccount=" + expectedAwsAccount + "]";
    }
}
