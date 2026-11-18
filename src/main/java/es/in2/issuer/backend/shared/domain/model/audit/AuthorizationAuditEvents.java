package es.in2.issuer.backend.shared.domain.model.audit;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code AuthorizationDecision} entry of one decision by powers, allowed or denied. The catalogue
 * has four reasons for a denial; a refusal that is not about powers (a type not enabled in the tenant, a
 * power that names a field twice) is not an authorization decision and has none.
 */
public final class AuthorizationAuditEvents {

    public static final String REASON_POWER_MISSING = "PowerMissing";
    public static final String REASON_OUT_OF_SCOPE = "OutOfScope";
    public static final String REASON_TENANT_MISMATCH = "TenantMismatch";
    public static final String REASON_PLATFORM_TENANT_READ_ONLY = "PlatformTenantReadOnly";

    /**
     * What was decided.
     *
     * @param requestedAction     the id of the matrix action, e.g. {@code E1}
     * @param evaluatedPower      the power that granted the action or was missing, when one was evaluated
     * @param userType            the user type the caller was recognized as
     * @param targetOrganization  the organization the action is about, when it has one
     */
    public record Decision(String requestedAction, String evaluatedPower, String userType, String targetOrganization) {
    }

    private AuthorizationAuditEvents() {
    }

    public static AuditEntry permitted(String resource, Decision decision) {
        return AuditEntry.success(AuditEventType.AUTHORIZATION_DECISION, resource, details(decision));
    }

    public static AuditEntry denied(String resource, String reason, Decision decision) {
        return AuditEntry.forReason(AuditEventType.AUTHORIZATION_DECISION, resource, reason, details(decision));
    }

    private static Map<String, Object> details(Decision decision) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("requested_action", decision.requestedAction());
        details.put("evaluated_power", decision.evaluatedPower());
        details.put("user_type", decision.userType());
        details.put("target_organization", decision.targetOrganization());
        return details;
    }
}
