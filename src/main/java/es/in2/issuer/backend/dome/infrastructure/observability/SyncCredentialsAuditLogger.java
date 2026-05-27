package es.in2.issuer.backend.dome.infrastructure.observability;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SyncCredentialsAuditLogger {

    private static final Logger auditLog = LoggerFactory.getLogger("audit.dome.sync_credentials");

    public void logSyncEvent(String tenant, String idempotencyKey, String outcome) {
        String sanitizedKey = sanitize(idempotencyKey);

        auditLog.info("event=SYNC_CREDENTIALS tenant={} idempotencyKey={} outcome={}",
                tenant, sanitizedKey, outcome);
    }

    private String sanitize(String input) {
        if (input == null || input.length() <= 8) return "***";
        return input.substring(0, 4) + "***" + input.substring(input.length() - 4);
    }
}