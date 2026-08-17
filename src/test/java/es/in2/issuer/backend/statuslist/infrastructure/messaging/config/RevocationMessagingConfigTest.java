package es.in2.issuer.backend.statuslist.infrastructure.messaging.config;

import com.fasterxml.jackson.databind.ObjectMapper;
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

    @Test
    void revocationRabbitCredentialsValidator_blankUsername_throwsIllegalStateException() throws Exception {
        RabbitProperties properties = new RabbitProperties();
        properties.setUsername("");
        properties.setPassword("secret");

        InitializingBean validator = config.revocationRabbitCredentialsValidator(properties);

        assertThatThrownBy(validator::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.rabbitmq.username");
    }

    @Test
    void revocationRabbitCredentialsValidator_blankPassword_throwsIllegalStateException() throws Exception {
        RabbitProperties properties = new RabbitProperties();
        properties.setUsername("issuer-svc");
        properties.setPassword(null);

        InitializingBean validator = config.revocationRabbitCredentialsValidator(properties);

        assertThatThrownBy(validator::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.rabbitmq.password");
    }

    @Test
    void revocationRabbitCredentialsValidator_bothCredentialsSet_doesNotThrow() throws Exception {
        RabbitProperties properties = new RabbitProperties();
        properties.setUsername("issuer-svc");
        properties.setPassword("secret");

        InitializingBean validator = config.revocationRabbitCredentialsValidator(properties);

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
