package es.in2.issuer.backend.statuslist.infrastructure.messaging.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig.RevocationMessagingProperties;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.retry.RepublishMessageRecoverer;
import org.springframework.amqp.support.converter.Jackson2JavaTypeMapper;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.amqp.RabbitProperties;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * F4 (EUD-225 {@code /verify}): only the fail-fast credential validator is unit-tested here
 * -- the rest of the topology (exchanges/queues/retry/DLQ) is exercised end-to-end by
 * RevocationInstructionListenerIT and RevocationInstructionSingleTenantIT against a real
 * broker, which is what actually proves it works, not a unit test of bean wiring.
 */
class RevocationMessagingConfigTest {

    private final RevocationMessagingConfig config = new RevocationMessagingConfig();

    private static RabbitProperties securedRabbitProperties() {
        RabbitProperties properties = new RabbitProperties();
        properties.setUsername("issuer-svc");
        properties.setPassword("secret");
        properties.getSsl().setEnabled(true);
        return properties;
    }

    @Test
    void revocationRabbitCredentialsValidator_blankUsername_throwsIllegalStateException() throws Exception {
        RabbitProperties properties = securedRabbitProperties();
        properties.setUsername("");

        InitializingBean validator = config.revocationRabbitCredentialsValidator(
                properties, new RevocationMessagingProperties(true, null, false));

        assertThatThrownBy(validator::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.rabbitmq.username");
    }

    @Test
    void revocationRabbitCredentialsValidator_blankPassword_throwsIllegalStateException() throws Exception {
        RabbitProperties properties = securedRabbitProperties();
        properties.setPassword(null);

        InitializingBean validator = config.revocationRabbitCredentialsValidator(
                properties, new RevocationMessagingProperties(true, null, false));

        assertThatThrownBy(validator::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.rabbitmq.password");
    }

    @Test
    void revocationRabbitCredentialsValidator_credentialsSetAndTlsEnabled_doesNotThrow() throws Exception {
        InitializingBean validator = config.revocationRabbitCredentialsValidator(
                securedRabbitProperties(), new RevocationMessagingProperties(true, null, false));

        assertThatCode(validator::afterPropertiesSet).doesNotThrowAnyException();
    }

    // ---------------------------------------------------------------- F13: TLS required

    @Test
    void revocationRabbitCredentialsValidator_tlsDisabledAndNoEscapeHatch_throwsIllegalStateException() throws Exception {
        RabbitProperties properties = securedRabbitProperties();
        properties.getSsl().setEnabled(false);

        InitializingBean validator = config.revocationRabbitCredentialsValidator(
                properties, new RevocationMessagingProperties(true, null, false));

        assertThatThrownBy(validator::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.rabbitmq.ssl.enabled");
    }

    @Test
    void revocationRabbitCredentialsValidator_tlsDisabledWithExplicitEscapeHatch_doesNotThrow() throws Exception {
        // The local Docker Compose profile's bundled RabbitMQ has no TLS listener --
        // allow-insecure-transport=true is the explicit, documented opt-out.
        RabbitProperties properties = securedRabbitProperties();
        properties.getSsl().setEnabled(false);

        InitializingBean validator = config.revocationRabbitCredentialsValidator(
                properties, new RevocationMessagingProperties(true, null, true));

        assertThatCode(validator::afterPropertiesSet).doesNotThrowAnyException();
    }

    @Test
    void revocationJsonMessageConverter_usesInferredTypePrecedence() {
        // F8 (EUD-225 /verify): a publisher-supplied __TypeId__ header must never influence
        // what class the payload deserializes into -- only the listener's own parameter type.
        Jackson2JsonMessageConverter converter = config.revocationJsonMessageConverter(new ObjectMapper());

        assertThat(converter.getTypePrecedence()).isEqualTo(Jackson2JavaTypeMapper.TypePrecedence.INFERRED);
    }

    @Test
    void safeDlqRecoverer_neverLeaksRawExceptionMessageOrStackTraceIntoDlqHeaders() {
        // F10 (EUD-225 /verify): the stock RepublishMessageRecoverer would put the raw
        // exception message and full stack trace into x-exception-message/
        // x-exception-stacktrace -- real internal detail that must never cross into a
        // broker plausibly operated by the client (on-premise, AD-7).
        RevocationMessagingConfig.SafeDlqRecoverer recoverer =
                new RevocationMessagingConfig.SafeDlqRecoverer(new RabbitTemplate(), RevocationMessagingConfig.DLX_NAME);
        Message message = new Message(new byte[0], new MessageProperties());
        RuntimeException internalDetail = new RuntimeException(
                "duplicate key value violates unique constraint \"revocation_instruction_inbox_pkey\" "
                        + "at jdbc:postgresql://internal-db.example.internal:5432/issuer");

        Map<String, Object> additionalHeaders = recoverer.additionalHeaders(message, internalDetail);

        // additionalHeaders() mutates the message's own header map directly and returns null
        // (nothing further for recover() to merge) -- assert against the message, not the
        // (deliberately empty) return value.
        assertThat(additionalHeaders).isNull();
        Map<String, Object> headers = message.getMessageProperties().getHeaders();
        assertThat(headers).doesNotContainKey(RepublishMessageRecoverer.X_EXCEPTION_STACKTRACE);
        assertThat(headers.get(RepublishMessageRecoverer.X_EXCEPTION_MESSAGE))
                .isEqualTo("RuntimeException");
        assertThat(headers.values()).noneMatch(v -> v.toString().contains("internal-db.example.internal"));
    }

    @Test
    void safeDlqRecoverer_nestedCause_reportsRootErrorType() {
        RevocationMessagingConfig.SafeDlqRecoverer recoverer =
                new RevocationMessagingConfig.SafeDlqRecoverer(new RabbitTemplate(), RevocationMessagingConfig.DLX_NAME);
        Message message = new Message(new byte[0], new MessageProperties());
        Exception rootCause = new IllegalStateException("root cause with internal detail");
        RuntimeException wrapper = new RuntimeException("wrapper", rootCause);

        recoverer.additionalHeaders(message, wrapper);

        assertThat(message.getMessageProperties().getHeaders().get(RepublishMessageRecoverer.X_EXCEPTION_MESSAGE))
                .isEqualTo("IllegalStateException");
    }
}
