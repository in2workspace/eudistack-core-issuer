package es.in2.issuer.backend.shared.infrastructure.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

class CredentialIssuedLoggerImplTest {

    private ListAppender<ILoggingEvent> appender;
    private CredentialIssuedLoggerImpl credentialIssuedLogger;

    @BeforeEach
    void setUp() {
        Logger logger = (Logger) LoggerFactory.getLogger(CredentialIssuedLoggerImpl.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        credentialIssuedLogger = new CredentialIssuedLoggerImpl();
    }

    @AfterEach
    void tearDown() {
        MDC.remove(TENANT_DOMAIN_CONTEXT_KEY);
        Logger logger = (Logger) LoggerFactory.getLogger(CredentialIssuedLoggerImpl.class);
        logger.detachAppender(appender);
    }

    @Test
    void logIssued_emitsInfoWithEventTenantAndOk() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg");

        credentialIssuedLogger.logIssued("learcredential.employee.w3c.4");

        assertThat(appender.list).hasSize(1);
        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.INFO);
        assertThat(event.getFormattedMessage())
                .contains("event=business.credential.issued")
                .contains("tenant=kpmg")
                .contains("configurationId=learcredential.employee.w3c.4")
                .contains("outcome=ok");
    }

    @Test
    void logFailed_emitsWarnWithEventTenantErrorAndErrorType() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg");

        credentialIssuedLogger.logFailed("learcredential.employee.w3c.4",
                new IllegalStateException("boom"));

        assertThat(appender.list).hasSize(1);
        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage())
                .contains("event=business.credential.issued")
                .contains("tenant=kpmg")
                .contains("configurationId=learcredential.employee.w3c.4")
                .contains("outcome=error")
                .contains("errorType=IllegalStateException");
    }

    @Test
    void logIssued_missingTenant_fallsBackToUnknown() {
        credentialIssuedLogger.logIssued("learcredential.employee.w3c.4");

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("tenant=unknown");
    }

    @Test
    void logIssued_blankTenant_fallsBackToUnknown() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "   ");

        credentialIssuedLogger.logIssued("learcredential.employee.w3c.4");

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("tenant=unknown");
    }

    @Test
    void logIssued_nullOrBlankConfigurationId_fallsBackToUnknown() {
        credentialIssuedLogger.logIssued(null);
        credentialIssuedLogger.logIssued("  ");

        assertThat(appender.list).hasSize(2);
        assertThat(appender.list.get(0).getFormattedMessage()).contains("configurationId=unknown");
        assertThat(appender.list.get(1).getFormattedMessage()).contains("configurationId=unknown");
    }

    @Test
    void logFailed_nullError_fallsBackToUnknownErrorType() {
        credentialIssuedLogger.logFailed("learcredential.employee.w3c.4", null);

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("errorType=unknown");
    }
}
