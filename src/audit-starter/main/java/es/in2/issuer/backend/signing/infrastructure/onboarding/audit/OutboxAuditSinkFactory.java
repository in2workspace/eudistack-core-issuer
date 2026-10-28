package es.in2.issuer.backend.signing.infrastructure.onboarding.audit;

import com.eudistack.auditoria.application.AuditPublisher;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.infrastructure.onboarding.AuditSinkFactory;
import es.in2.issuer.backend.signing.infrastructure.onboarding.AuditSinkHandle;
import es.in2.issuer.backend.signing.infrastructure.onboarding.SigningConfigurationAuditSink;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import javax.sql.DataSource;

/**
 * Starts the minimal non-web Spring context of {@link OutboxAuditConfiguration} and hands out the outbox sink. It is
 * loaded by name from {@code OnboardingWiring} when {@code OWN_KEY_AUDIT_SINK=outbox}.
 *
 * <p>Publisher on, dispatcher off, source {@code issuer}, no web application and no configuration file: they are
 * command line arguments, which win over
 * environment variables, so a stray {@code AUDITORIA_DISPATCHER_ENABLED} cannot start a dispatcher here.
 */
public class OutboxAuditSinkFactory implements AuditSinkFactory {

    @Override
    public AuditSinkHandle open(DataSource dataSource) {
        // The tool configures its own logging (logback-onboarding.xml): Spring Boot must not replace it. The
        // property is only read while the application starts.
        String previous = System.getProperty(LoggingSystem.SYSTEM_PROPERTY);
        System.setProperty(LoggingSystem.SYSTEM_PROPERTY, LoggingSystem.NONE);
        try {
            ConfigurableApplicationContext context = new SpringApplicationBuilder(OutboxAuditConfiguration.class)
                    .web(WebApplicationType.NONE)
                    .bannerMode(org.springframework.boot.Banner.Mode.OFF)
                    .logStartupInfo(false)
                    .registerShutdownHook(false)
                    .initializers((GenericApplicationContext applicationContext) ->
                            applicationContext.registerBean("dataSource", DataSource.class, () -> dataSource))
                    .run("--auditoria.publisher.enabled=true", "--auditoria.dispatcher.enabled=false",
                            "--auditoria.source=issuer",
                            // Not the Issuer's application.yml (it makes the application reactive): a file name
                            // that does not exist, so no configuration file is read.
                            "--spring.config.name=own-key-onboarding-tool", "--spring.main.web-application-type=none");
            return new OutboxHandle(context);
        } catch (RuntimeException e) {
            throw new OnboardingFailedException("the audit outbox could not be started: " + e.getMessage(), e);
        } finally {
            if (previous == null) {
                System.clearProperty(LoggingSystem.SYSTEM_PROPERTY);
            } else {
                System.setProperty(LoggingSystem.SYSTEM_PROPERTY, previous);
            }
        }
    }

    /** The sink and the Spring context behind it; the context is closed when the run ends. */
    static final class OutboxHandle implements AuditSinkHandle {

        private final ConfigurableApplicationContext context;
        private final SigningConfigurationAuditSink sink;

        OutboxHandle(ConfigurableApplicationContext context) {
            this.context = context;
            this.sink = new OutboxSigningConfigurationAuditSink(context.getBean(AuditPublisher.class));
        }

        ConfigurableApplicationContext context() {
            return context;
        }

        @Override
        public SigningConfigurationAuditSink sink() {
            return sink;
        }

        @Override
        public void close() {
            context.close();
        }
    }
}
