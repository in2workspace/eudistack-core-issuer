package es.in2.issuer.backend.statuslist.infrastructure.messaging.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.support.converter.Jackson2JavaTypeMapper;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.amqp.RabbitProperties;

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
}
