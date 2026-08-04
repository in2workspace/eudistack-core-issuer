package es.in2.issuer.backend.shared.infrastructure.service;

import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuditServiceImpl implements AuditService {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");
    private static final Logger LOG = LoggerFactory.getLogger(AuditServiceImpl.class);

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

    @Override
    public void auditAttempted(String event, String userId, String resourceType, String resourceId,
                               Map<String, Object> details) {
        try {
            MDC.put("audit.event", event);
            MDC.put("audit.outcome", "attempted");
            if (userId != null) MDC.put("audit.userId", userId);
            if (resourceType != null) MDC.put("audit.resourceType", resourceType);
            if (resourceId != null) MDC.put("audit.resourceId", resourceId);

            AUDIT.info("event={} outcome=attempted userId={} resourceType={} resourceId={} details=\"{}\"",
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
    public void auditDelivery(DeliveryTrace trace) {
        try {
            boolean hasFailure = trace.hasFailure();
            String resultsField = formatResults(trace.results());

            MDC.put("audit.event", DeliveryTrace.EVENT_NAME);
            MDC.put("tenant.id", trace.tenantId());

            if (hasFailure) {
                AUDIT.warn("event={} tenant.id={} processId={} results={}",
                        DeliveryTrace.EVENT_NAME, trace.tenantId(), trace.processId(), resultsField);
            } else {
                AUDIT.info("event={} tenant.id={} processId={} results={}",
                        DeliveryTrace.EVENT_NAME, trace.tenantId(), trace.processId(), resultsField);
            }
        } catch (RuntimeException e) {
            // Best-effort (ES-03/ES-04): the delivery already happened, a broken audit channel
            // must never surface as a failure of the caller. Log locally so the signal isn't lost.
            LOG.warn("Failed to emit delivery audit trace for processId={}",
                    trace != null ? trace.processId() : "unknown", e);
        } finally {
            clearAuditMdc();
            MDC.remove("tenant.id");
        }
    }

    private String formatResults(Set<DeliveryResult> results) {
        return results.stream()
                .map(r -> r.error() != null
                        ? r.mode() + "=" + r.status() + "(" + r.error() + ")"
                        : r.mode() + "=" + r.status())
                .collect(Collectors.joining(","));
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
