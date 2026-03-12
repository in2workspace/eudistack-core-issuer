package es.in2.issuer.backend.shared.domain.service;

import java.util.Map;

/**
 * Structured audit logging for ENS/NIS2 compliance.
 * Emits structured events via a dedicated AUDIT logger.
 */
public interface AuditService {

    void auditSuccess(String event, String userId, String resourceType, String resourceId,
                      Map<String, Object> details);

    void auditFailure(String event, String userId, String reason,
                      Map<String, Object> details);
}
