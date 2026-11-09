package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;

import java.util.Map;

/**
 * Structured audit logging for ENS/NIS2 compliance.
 * Emits structured events via a dedicated AUDIT logger.
 */
public interface AuditService {

    void auditSuccess(String event, String userId, String resourceType, String resourceId,
                      Map<String, Object> details);

    /**
     * {@link #auditSuccess(String, String, String, String, Map)} with the {@code organization} the operation
     * belongs to, recorded next to the user and not inside {@code details}, as the canonical
     * {@code organization} of the EUD-244 audit record. {@code null} leaves it out.
     */
    void auditSuccess(String event, String userId, String organization, String resourceType, String resourceId,
                      Map<String, Object> details);

    void auditFailure(String event, String userId, String reason,
                      Map<String, Object> details);

    /** {@link #auditFailure(String, String, String, Map)} with the {@code organization}, as above. */
    void auditFailure(String event, String userId, String organization, String reason,
                      Map<String, Object> details);

    void auditAttempted(String event, String userId, String resourceType, String resourceId,
                        Map<String, Object> details);

    /**
     * Audits how a credential was delivered: mode(s) applied, per-mode result and tenant
     * (EUD-170 / US-04, AC-01/AC-04). Best-effort — implementations MUST NOT let a failure
     * of the audit channel propagate to the caller (ES-03/ES-04).
     */
    void auditDelivery(DeliveryTrace trace);
}
