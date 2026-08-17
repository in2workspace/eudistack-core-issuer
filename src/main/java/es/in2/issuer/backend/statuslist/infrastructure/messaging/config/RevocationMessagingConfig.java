package es.in2.issuer.backend.statuslist.infrastructure.messaging.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.amqp.AmqpRejectAndDontRequeueException;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.FanoutExchange;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.rabbit.config.RetryInterceptorBuilder;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.retry.RepublishMessageRecoverer;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.backoff.ExponentialBackOffPolicy;
import org.springframework.retry.interceptor.RetryOperationsInterceptor;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;

import java.util.Map;

/**
 * RabbitMQ topology + consumer resilience for the revocation-instruction queue (EUD-225,
 * AD-5/AD-6). Entirely inert unless {@code issuer.messaging.revocation.enabled=true}: no
 * bean here is created, no queue is declared, no broker connectivity is required — this is
 * the deploy-safety mechanism behind AC-10/NFR-S-225-06.
 * <p>
 * Retry semantics (AD-5): a stateless Spring Retry interceptor wraps the
 * {@code @RabbitListener} invocation — 3 attempts, exponential backoff 1s → 2s → 4s (capped
 * at 8s) — for every exception <b>except</b> {@link AmqpRejectAndDontRequeueException}, which
 * a permanent error is expected to throw and which skips straight to the recoverer with zero
 * retries. Either way, retries exhausted or not, the recoverer republishes to the DLX with
 * {@code x-exception-*} headers rather than nacking, so the original queue never sees the
 * message again. Message-conversion failures (malformed payload) never reach the listener or
 * this interceptor at all: {@code MessageConversionException} is one of Spring AMQP's default
 * "fatal" exceptions, rejected without requeue by the container itself, which the queue's own
 * {@code x-dead-letter-exchange} then routes to the same DLX — no code here needed for that path.
 */
@Configuration
@ConditionalOnProperty(name = "issuer.messaging.revocation.enabled", havingValue = "true")
public class RevocationMessagingConfig {

    public static final String EXCHANGE_NAME = "eudistack.revocation";
    public static final String ROUTING_KEY = "revocation.instruction";
    public static final String QUEUE_NAME = "eudistack.revocation.instructions";
    public static final String DLX_NAME = "eudistack.revocation.dlx";
    public static final String DLQ_NAME = "eudistack.revocation.instructions.dlq";

    // NFR-S-225-02 (proposed, spec-deltas.md SD-01)
    private static final int RETRY_MAX_ATTEMPTS = 3;
    private static final long RETRY_INITIAL_INTERVAL_MS = 1_000L;
    private static final double RETRY_MULTIPLIER = 2.0;
    private static final long RETRY_MAX_INTERVAL_MS = 8_000L;

    // NFR-S-225-03 (proposed): broker-level backstop so a recoverer failure can't loop forever.
    private static final int DELIVERY_LIMIT = 5;

    // AD-4 defense in depth: reduces (does not eliminate) the EC-03 overlapping-redelivery window.
    private static final int PREFETCH_COUNT = 1;
    private static final int CONCURRENT_CONSUMERS = 1;

    @Bean
    DirectExchange revocationExchange() {
        return new DirectExchange(EXCHANGE_NAME, true, false);
    }

    @Bean
    FanoutExchange revocationDeadLetterExchange() {
        return new FanoutExchange(DLX_NAME, true, false);
    }

    @Bean
    Queue revocationInstructionsQueue() {
        return QueueBuilder.durable(QUEUE_NAME)
                .quorum()
                .deadLetterExchange(DLX_NAME)
                .withArgument("x-delivery-limit", DELIVERY_LIMIT)
                .build();
    }

    @Bean
    Queue revocationInstructionsDlq() {
        return QueueBuilder.durable(DLQ_NAME)
                .quorum()
                .build();
    }

    @Bean
    Binding revocationInstructionsBinding(Queue revocationInstructionsQueue, DirectExchange revocationExchange) {
        return BindingBuilder.bind(revocationInstructionsQueue).to(revocationExchange).with(ROUTING_KEY);
    }

    @Bean
    Binding revocationInstructionsDlqBinding(Queue revocationInstructionsDlq, FanoutExchange revocationDeadLetterExchange) {
        return BindingBuilder.bind(revocationInstructionsDlq).to(revocationDeadLetterExchange);
    }

    @Bean
    Jackson2JsonMessageConverter revocationJsonMessageConverter(ObjectMapper objectMapper) {
        return new Jackson2JsonMessageConverter(objectMapper);
    }

    @Bean
    RetryOperationsInterceptor revocationRetryInterceptor(RabbitTemplate rabbitTemplate) {
        ExponentialBackOffPolicy backOffPolicy = new ExponentialBackOffPolicy();
        backOffPolicy.setInitialInterval(RETRY_INITIAL_INTERVAL_MS);
        backOffPolicy.setMultiplier(RETRY_MULTIPLIER);
        backOffPolicy.setMaxInterval(RETRY_MAX_INTERVAL_MS);

        // Every exception retries up to RETRY_MAX_ATTEMPTS, except a permanent error explicitly
        // signalled via AmqpRejectAndDontRequeueException, which the recoverer handles immediately.
        SimpleRetryPolicy retryPolicy = new SimpleRetryPolicy(
                RETRY_MAX_ATTEMPTS,
                Map.of(AmqpRejectAndDontRequeueException.class, false),
                true,
                true
        );

        RetryTemplate retryTemplate = new RetryTemplate();
        retryTemplate.setBackOffPolicy(backOffPolicy);
        retryTemplate.setRetryPolicy(retryPolicy);

        return RetryInterceptorBuilder.stateless()
                .retryOperations(retryTemplate)
                .recoverer(new RepublishMessageRecoverer(rabbitTemplate, DLX_NAME))
                .build();
    }

    @Bean
    SimpleRabbitListenerContainerFactory revocationListenerContainerFactory(
            ConnectionFactory connectionFactory,
            Jackson2JsonMessageConverter revocationJsonMessageConverter,
            RetryOperationsInterceptor revocationRetryInterceptor
    ) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(revocationJsonMessageConverter);
        factory.setPrefetchCount(PREFETCH_COUNT);
        factory.setConcurrentConsumers(CONCURRENT_CONSUMERS);
        factory.setAdviceChain(revocationRetryInterceptor);
        factory.setDefaultRequeueRejected(false);
        return factory;
    }

    /**
     * Type-safe binding for {@code issuer.messaging.revocation.*}. Registered independently of
     * this {@code @Configuration} class's own {@code @ConditionalOnProperty} (via
     * {@code @ConfigurationPropertiesScan} on the application class) so that {@code enabled}
     * itself, and the future AD-8 {@code tenant-binding} value, are always bindable — including
     * in the disabled default, where {@link RevocationMessagingConfig} declares no bean at all.
     */
    @ConfigurationProperties(prefix = "issuer.messaging.revocation")
    public record RevocationMessagingProperties(boolean enabled) {
    }
}
