package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.model.SigningModality;

import java.time.Duration;
import java.time.Instant;

/**
 * Audit event {@code SigningConfigurationChanged} (EUD-244 catalogue, action {@code ConfigureSigning}): a
 * tenant's signing configuration was created or replaced, or the attempt was rejected. There is no
 * withdrawal command: a configuration is only withdrawn by its replacement, which is {@code REPLACE}.
 * {@code RETIRE} is the retirement of the KMS key of a replaced configuration, by {@code reconcile}, or a
 * {@code discard} that was denied; it has no new modality and no certificate.
 *
 * <p>It carries no secrets and no key reference: only the fingerprint of the signing certificate, which is
 * public. The actor is the ARN of the AWS caller, the same value as {@code activated_by}.
 *
 * @param tenant                   tenant id
 * @param operation                create or replace
 * @param result                   success, or denied for a rejected onboarding
 * @param reason                   why it was rejected; {@code null} on success
 * @param previousModality         modality of the configuration that was active, {@code null} if none
 * @param newModality              modality of the new configuration; {@code null} for a retirement
 * @param signingCertificateSha256 SHA-256 of the leaf certificate, hexadecimal; {@code null} if the chain could
 *                                 not be read
 * @param actor                    ARN of the caller
 * @param duration                 how long the onboarding took until the event
 * @param occurredAt               when the event happened
 * @param correlationId            the operation id of the onboarding, {@code null} while none was generated
 */
public record SigningConfigurationChanged(
        String tenant,
        Operation operation,
        Result result,
        RejectionReason reason,
        SigningModality previousModality,
        SigningModality newModality,
        String signingCertificateSha256,
        String actor,
        Duration duration,
        Instant occurredAt,
        String correlationId
) {

    /**
     * The retirement of the KMS key of a withdrawn own-key configuration. No key reference goes into the event.
     *
     * @param correlationId the id of the configuration (or operation) concerned
     */
    public static SigningConfigurationChanged retire(String tenant, Result result, RejectionReason reason, String actor,
                                                     Duration duration, Instant occurredAt, String correlationId) {
        return new SigningConfigurationChanged(tenant, Operation.RETIRE, result, reason, SigningModality.OWN_KEY, null,
                null, actor, duration, occurredAt, correlationId);
    }

    public enum Operation {
        CREATE("Create"),
        REPLACE("Replace"),
        RETIRE("Retire");

        private final String catalogName;

        Operation(String catalogName) {
            this.catalogName = catalogName;
        }

        public String catalogName() {
            return catalogName;
        }
    }

    public enum Result {
        SUCCESS("Success"),
        DENIED("Denied"),
        FAILURE("Failure");

        private final String catalogName;

        Result(String catalogName) {
            this.catalogName = catalogName;
        }

        public String catalogName() {
            return catalogName;
        }
    }
}
