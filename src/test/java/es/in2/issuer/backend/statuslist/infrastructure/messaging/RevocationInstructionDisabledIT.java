package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC-10 / NFR-S-225-06: deploy-safety of {@code issuer.messaging.revocation.enabled=false}
 * (the default). Deliberately reuses the same Spring context {@link PostgresIntegrationBase}
 * gives every other IT in the repo (no broker, no messaging property overrides) — proving the
 * feature is inert in exactly the environment every non-messaging IT already runs in, rather
 * than a specially-crafted "disabled" context that could hide a leaking bean definition. That
 * shared context is also exercised end-to-end by dozens of other ITs (ClientCredentialsTokenIT,
 * IntakeAuthenticationGateIT, ...), so "existing flows behave exactly as before" doesn't need a
 * redundant check here.
 * <p>
 * Note: {@code spring-boot-starter-amqp} being on the classpath means Spring Boot's own
 * {@code RabbitAutoConfiguration} always creates a base {@code ConnectionFactory} bean,
 * regardless of this Story's property — harmless (lazy, never connects unless used) and not
 * part of what AC-10 asks to stay absent. What must stay absent is the actual topology
 * ({@link RevocationMessagingConfig}'s exchange/queue/DLQ/binding beans) and the listener.
 */
class RevocationInstructionDisabledIT extends PostgresIntegrationBase {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void contextStartsWithoutAnyMessagingTopologyOrListener() {
        assertThat(applicationContext.getBeansOfType(RevocationInstructionListener.class)).isEmpty();
        assertThat(applicationContext.getBeansOfType(RevocationMessagingConfig.class)).isEmpty();
        assertThat(applicationContext.containsBean("revocationExchange")).isFalse();
        assertThat(applicationContext.containsBean("revocationInstructionsQueue")).isFalse();
        assertThat(applicationContext.containsBean("revocationInstructionsDlq")).isFalse();
        assertThat(applicationContext.containsBean("revocationListenerContainerFactory")).isFalse();
    }
}
