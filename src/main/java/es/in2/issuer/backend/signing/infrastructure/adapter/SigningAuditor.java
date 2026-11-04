package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.signing.domain.exception.CertificateCheckException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.signing.infrastructure.csc.CertificateQualificationUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Records signing attempts in the audit trail, through {@link AuditService}.
 *
 * <p>Every attempt carries tenant, object, modality, provider, outcome, reason (failures) and
 * duration. It never carries the payload, the JWS, tokens, the KMS key reference, digests, e-mail or
 * secrets: callers only hand over classification data, and the reason is the
 * {@code SigningFailureReason} name, never an exception message.
 *
 * <p>Own-key attempts also carry their certificate (EUD-251 FR-14, AC-20): the local check that failed,
 * or {@code passed}; whether the certificate is qualified; and the trust validation, which reads
 * {@code not_performed} until EUD-264 validates the chain against the European trust lists.
 *
 * <p>Out of scope here: audit of configuration changes (alta, sustitución, retirada, alta rechazada).
 * Those operations are performed outside the Issuer, so the Issuer cannot record them.
 *
 * <p>Best-effort: a failure of the audit channel is logged and never reaches the signing flow.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SigningAuditor {

    public static final String SIGN_EVENT = "signing.attempt";
    public static final String SELF_TEST_EVENT = "signing.self_test";
    public static final String QTSP_MODALITY = "qtsp";
    public static final String OWN_KEY_MODALITY = "own_key";
    public static final String KMS_PROVIDER = "aws-kms";
    public static final String UNKNOWN = "unknown";
    static final String CERTIFICATE_CHECKS_PASSED = "passed";
    static final String TRUST_VALIDATION_NOT_PERFORMED = "not_performed";

    private static final String RESOURCE_TYPE = "signing";

    private final AuditService auditService;

    /**
     * What a signing attempt was about. {@code object} is a non-sensitive kind of thing signed (for
     * example {@code JADES/jwt}); {@code issuanceId} may be {@code null}, and so may
     * {@code qualifiedCertificate} when the attempt has no own-key configuration.
     */
    public record Attempt(String tenant, String object, String issuanceId, String modality, String provider,
                          long durationMs, Boolean qualifiedCertificate) { }

    /** Whether the own-key certificate is a qualified seal; {@code null} for any other configuration. */
    public static Boolean qualifiedCertificate(ActiveSigningConfig config) {
        if (config == null || config.modality() != SigningModality.OWN_KEY) {
            return null;
        }
        return CertificateQualificationUtils.isQualifiedSeal(config.ownKey().certificateChain());
    }

    public void success(String event, Attempt attempt) {
        try {
            auditService.auditSuccess(event, null, RESOURCE_TYPE, null, details(attempt, "success", null));
        } catch (RuntimeException e) {
            logAuditFailure(event, e);
        }
    }

    public void failure(String event, Attempt attempt, Throwable error) {
        try {
            auditService.auditFailure(event, null, SigningFailureReasons.of(error).name(),
                    details(attempt, "failure", error));
        } catch (RuntimeException e) {
            logAuditFailure(event, e);
        }
    }

    private static Map<String, Object> details(Attempt attempt, String outcome, Throwable error) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant", orUnknown(attempt.tenant()));
        details.put("object", orUnknown(attempt.object()));
        if (attempt.issuanceId() != null) {
            details.put("issuanceId", attempt.issuanceId());
        }
        details.put("modality", orUnknown(attempt.modality()));
        details.put("provider", orUnknown(attempt.provider()));
        details.put("outcome", outcome);
        details.put("durationMs", attempt.durationMs());
        putCertificate(details, attempt, error);
        return details;
    }

    /**
     * A failed check is recorded even before a configuration is resolved: the certificate may have failed
     * while it was being loaded. {@code passed} is only known on success, since a failure after the checks
     * (KMS unavailable, for example) does not say whether they ran.
     */
    private static void putCertificate(Map<String, Object> details, Attempt attempt, Throwable error) {
        boolean ownKey = OWN_KEY_MODALITY.equals(attempt.modality());
        if (error != null) {
            CertificateCheckException.of(error)
                    .ifPresent(check -> details.put("certificateCheck", check.auditValue()));
        } else if (ownKey) {
            details.put("certificateCheck", CERTIFICATE_CHECKS_PASSED);
        }
        if (ownKey) {
            if (attempt.qualifiedCertificate() != null) {
                details.put("certificateQualified", attempt.qualifiedCertificate());
            }
            details.put("trustValidation", TRUST_VALIDATION_NOT_PERFORMED);
        }
    }

    private static String orUnknown(String value) {
        return value == null || value.isBlank() ? UNKNOWN : value;
    }

    private static void logAuditFailure(String event, RuntimeException e) {
        log.warn("could not record audit event={}: {}", event, e.getClass().getSimpleName());
    }
}
