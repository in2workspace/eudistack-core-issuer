package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.statuslist.application.HandleRevocationInstructionWorkflow;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.exception.UnknownTenantException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.AmqpRejectAndDontRequeueException;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Inbound AMQP adapter for the revocation-instruction queue (EUD-225). The non-HTTP
 * equivalent of {@code TenantDomainWebFilter}: resolves and validates the tenant before
 * touching any repository, then bridges into the reactive pipeline with a bounded
 * {@code block()} (AD-5) — an intentional, documented exception to
 * {@code conv-webflux-guidelines.md} confined to the AMQP container's own thread pool
 * (never the Netty event loop), dimensioned by {@code prefetch=1}/{@code concurrency=1}
 * (see {@link RevocationMessagingConfig}).
 * <p>
 * Inert unless {@code issuer.messaging.revocation.enabled=true} (AC-10).
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "issuer.messaging.revocation.enabled", havingValue = "true")
public class RevocationInstructionListener {

    // NFR-S-225-05 (proposed, spec-deltas.md SD-01)
    private static final Duration PROCESSING_TIMEOUT = Duration.ofSeconds(30);

    // Same criterion as TenantDomainWebFilter: letters, digits, hyphens, underscores only
    // (also prevents search_path injection).
    private static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    private final RevocationInstructionMessageMapper mapper;
    private final HandleRevocationInstructionWorkflow workflow;
    private final RevocationInstructionErrorClassifier errorClassifier;
    private final TenantRegistryService tenantRegistryService;

    @RabbitListener(queues = RevocationMessagingConfig.QUEUE_NAME, containerFactory = "revocationListenerContainerFactory")
    public void onMessage(RevocationInstructionMessage message,
                          @Header(value = AmqpHeaders.MESSAGE_ID, required = false) String amqpMessageIdProperty) {
        String processId = UUID.randomUUID().toString();
        try {
            RevocationInstruction instruction = mapper.toDomain(message, amqpMessageIdProperty, Instant.now());
            log.info("processId={} action=onMessage status=received messageId={} issuanceId={}",
                    processId, instruction.messageId(), instruction.issuanceId());

            validateTenantFormat(instruction.tenantId());

            buildPipeline(processId, instruction)
                    .timeout(PROCESSING_TIMEOUT)
                    .block();

            log.info("processId={} action=onMessage status=ack messageId={}", processId, instruction.messageId());
        } catch (RuntimeException e) {
            handleFailure(processId, e);
        }
    }

    private Mono<Void> buildPipeline(String processId, RevocationInstruction instruction) {
        String tenantId = instruction.tenantId();
        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(activeSchemas -> {
                    if (!activeSchemas.contains(tenantId)) {
                        return Mono.<Void>error(new UnknownTenantException(tenantId));
                    }
                    return workflow.handleRevocationInstruction(processId, instruction);
                })
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenantId));
    }

    private void validateTenantFormat(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            // Modo multi-tenant por defecto (sin AD-8 tenant-binding aún cableado): el campo
            // es obligatorio. AC-13 exige exactamente este comportamiento como invariante.
            throw new InvalidRevocationInstructionException("Revocation instruction is missing tenantId");
        }
        if (!TENANT_NAME_PATTERN.matcher(tenantId).matches()) {
            throw new InvalidRevocationInstructionException("Revocation instruction tenantId has an invalid format: " + tenantId);
        }
    }

    private void handleFailure(String processId, RuntimeException error) {
        Throwable cause = Exceptions.unwrap(error);

        if (errorClassifier.isRetryable(cause)) {
            log.warn("processId={} action=onMessage status=retryable error={}", processId, cause.toString());
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            throw new IllegalStateException(cause);
        }

        log.warn("processId={} action=onMessage status=permanent error={}", processId, cause.toString());
        throw new AmqpRejectAndDontRequeueException("Permanent revocation instruction failure: " + cause.getMessage(), cause);
    }
}
