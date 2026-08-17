package es.in2.issuer.backend.statuslist.infrastructure.messaging.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.statuslist.domain.model.RevocationTenantBinding;
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
import org.springframework.amqp.support.converter.Jackson2JavaTypeMapper;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.amqp.RabbitProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.backoff.ExponentialBackOffPolicy;
import org.springframework.retry.interceptor.RetryOperationsInterceptor;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;

import java.util.Map;
import java.util.regex.Pattern;

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

    // F6 (EUD-225 /verify): backstop against unbounded queue growth if consumers stop
    // entirely (deploy misconfiguration, sustained outage) -- oldest messages are dropped
    // (dead-lettered, same DLX as x-delivery-limit) once this is exceeded, rather than the
    // queue growing without limit.
    private static final int MAX_QUEUE_LENGTH = 10_000;

    /**
     * F4 (EUD-225 {@code /verify}): this channel's entire authorization model rests on the
     * broker credential (AD-7) — silently falling back to RabbitMQ's own well-known
     * {@code guest}/{@code guest} account (no longer the default in {@code application.yml})
     * is the wrong failure mode for something irreversible. Fails fast at startup, only when
     * the feature is actually enabled — {@link InitializingBean#afterPropertiesSet()} runs
     * during this bean's own initialization, so a blank credential aborts context startup
     * with a clear cause instead of the consumer silently authenticating as {@code guest}
     * (or simply failing to connect, with no diagnosis of why).
     */
    @Bean
    InitializingBean revocationRabbitCredentialsValidator(RabbitProperties rabbitProperties) {
        return () -> {
            if (isBlank(rabbitProperties.getUsername()) || isBlank(rabbitProperties.getPassword())) {
                throw new IllegalStateException(
                        "issuer.messaging.revocation.enabled=true requires spring.rabbitmq.username and "
                                + "spring.rabbitmq.password to be set explicitly -- refusing to start with "
                                + "RabbitMQ's default guest/guest account for a channel whose entire "
                                + "authorization model rests on the broker credential (AD-7)");
            }
        };
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

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
                .maxLength(MAX_QUEUE_LENGTH)
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
        Jackson2JsonMessageConverter converter = new Jackson2JsonMessageConverter(objectMapper);
        // F8 (EUD-225 /verify): the default TypePrecedence.TYPE_ID lets a publisher-supplied
        // __TypeId__ header pick the target class, which is safe today only because the
        // concrete RevocationInstructionListener.onMessage(RevocationInstructionMessage, ...)
        // signature happens to constrain it -- a future refactor of the listener could
        // silently reopen a polymorphic-deserialization vector. INFERRED removes the header
        // from the decision entirely: the listener's own parameter type is always what
        // deserialization targets, regardless of what a message header claims.
        converter.setTypePrecedence(Jackson2JavaTypeMapper.TypePrecedence.INFERRED);
        return converter;
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
     * and {@code tenantBinding} are always bindable — including in the disabled default, where
     * {@link RevocationMessagingConfig} declares no bean at all.
     * <p>
     * {@code tenantBinding} is AD-8's single-tenant deployment declaration: absent/blank by
     * default (multi-tenant mode, untouched). Its <b>format</b> — not its existence in
     * {@code tenant_registry}, which depends on the database and is checked when a message is
     * actually processed (EC-07) — is validated fail-fast at startup, exactly like
     * {@code TenantDomainWebFilter}'s tenant name pattern.
     */
    @ConfigurationProperties(prefix = "issuer.messaging.revocation")
    public record RevocationMessagingProperties(boolean enabled, String tenantBinding) {

        private static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

        public RevocationMessagingProperties {
            if (tenantBinding != null && !tenantBinding.isBlank()
                    && !TENANT_NAME_PATTERN.matcher(tenantBinding).matches()) {
                throw new IllegalArgumentException(
                        "issuer.messaging.revocation.tenant-binding has an invalid format: " + tenantBinding);
            }
        }

        /** {@link RevocationTenantBinding#none()} when the deployment declares nothing. */
        public RevocationTenantBinding toRevocationTenantBinding() {
            return (tenantBinding == null || tenantBinding.isBlank())
                    ? RevocationTenantBinding.none()
                    : RevocationTenantBinding.of(tenantBinding);
        }
    }
}
