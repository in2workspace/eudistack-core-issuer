package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Records signing attempts in the audit trail (EUD-289 AC-19), through {@link AuditService}.
 *
 * <p>Every attempt carries tenant, object, modality, provider, outcome, reason (failures) and
 * duration. It never carries the payload, the JWS, tokens, the KMS key reference, digests, e-mail or
 * secrets: callers only hand over classification data, and the reason is the
 * {@code SigningFailureReason} name, never an exception message.
 *
 * <p>Out of scope here: audit of configuration changes (alta, sustitución, retirada, alta rechazada).
 * Those operations are performed by the onboarding tool (EUD-289 task B8), not by the Issuer, so the
 * Issuer cannot record them.
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

    private static final String RESOURCE_TYPE = "signing";

    private final AuditService auditService;

    /**
     * What a signing attempt was about. {@code object} is a non-sensitive kind of thing signed (for
     * example {@code JADES/jwt}); {@code issuanceId} may be {@code null}.
     */
    public record Attempt(String tenant, String object, String issuanceId, String modality, String provider,
                          long durationMs) { }

    public void success(String event, Attempt attempt) {
        try {
            auditService.auditSuccess(event, null, RESOURCE_TYPE, null, details(attempt, "success"));
        } catch (RuntimeException e) {
            logAuditFailure(event, e);
        }
    }

    public void failure(String event, Attempt attempt, Throwable error) {
        try {
            auditService.auditFailure(event, null, SigningFailureReasons.of(error).name(),
                    details(attempt, "failure"));
        } catch (RuntimeException e) {
            logAuditFailure(event, e);
        }
    }

    private static Map<String, Object> details(Attempt attempt, String outcome) {
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
        return details;
    }

    private static String orUnknown(String value) {
        return value == null || value.isBlank() ? UNKNOWN : value;
    }

    private static void logAuditFailure(String event, RuntimeException e) {
        log.warn("could not record audit event={}: {}", event, e.getClass().getSimpleName());
    }
}
