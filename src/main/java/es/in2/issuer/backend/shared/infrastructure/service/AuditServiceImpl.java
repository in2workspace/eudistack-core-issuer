package es.in2.issuer.backend.shared.infrastructure.service;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuditServiceImpl implements AuditService {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    @Override
    public void auditSuccess(String event, String userId, String resourceType, String resourceId,
                             Map<String, Object> details) {
        try {
            MDC.put("audit.event", event);
            MDC.put("audit.outcome", "success");
            if (userId != null) MDC.put("audit.userId", userId);
            if (resourceType != null) MDC.put("audit.resourceType", resourceType);
            if (resourceId != null) MDC.put("audit.resourceId", resourceId);

            AUDIT.info("event={} outcome=success userId={} resourceType={} resourceId={} {}",
                    event,
                    userId != null ? userId : "system",
                    resourceType != null ? resourceType : "",
                    resourceId != null ? resourceId : "",
                    formatDetails(details));
        } finally {
            clearAuditMdc();
        }
    }

    @Override
    public void auditFailure(String event, String userId, String reason,
                             Map<String, Object> details) {
        try {
            MDC.put("audit.event", event);
            MDC.put("audit.outcome", "failure");
            if (userId != null) MDC.put("audit.userId", userId);

            AUDIT.warn("event={} outcome=failure userId={} reason={} {}",
                    event,
                    userId != null ? userId : "system",
                    reason != null ? reason : "",
                    formatDetails(details));
        } finally {
            clearAuditMdc();
        }
    }

    private void clearAuditMdc() {
        MDC.remove("audit.event");
        MDC.remove("audit.outcome");
        MDC.remove("audit.userId");
        MDC.remove("audit.resourceType");
        MDC.remove("audit.resourceId");
    }

    private String formatDetails(Map<String, Object> details) {
        if (details == null || details.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        details.forEach((k, v) -> sb.append(k).append('=').append(v).append(' '));
        return sb.toString().trim();
    }
}
