package es.in2.issuer.backend.shared.infrastructure.service;

import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class CredentialIssuedLoggerImpl implements CredentialIssuedLogger {

    private static final String EVENT = "business.credential.issued";
    private static final String UNKNOWN = "unknown";

    @Override
    public void logIssued(String configurationId) {
        log.info("event={} tenant={} configurationId={} outcome=ok",
                EVENT, currentTenant(), safeTag(configurationId));
    }

    @Override
    public void logFailed(String configurationId, Throwable error) {
        log.warn("event={} tenant={} configurationId={} outcome=error errorType={}",
                EVENT, currentTenant(), safeTag(configurationId), errorType(error));
    }

    private static String errorType(Throwable error) {
        return error == null ? UNKNOWN : error.getClass().getSimpleName();
    }

    private static String safeTag(String value) {
        return value == null || value.isBlank() ? UNKNOWN : value;
    }

    private static String currentTenant() {
        String tenant = MDC.get(TENANT_DOMAIN_CONTEXT_KEY);
        return tenant == null || tenant.isBlank() ? UNKNOWN : tenant;
    }
}
