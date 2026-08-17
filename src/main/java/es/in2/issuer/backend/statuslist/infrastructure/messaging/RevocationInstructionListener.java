package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.util.TenantIdentifiers;
import es.in2.issuer.backend.statuslist.application.HandleRevocationInstructionWorkflow;
import es.in2.issuer.backend.statuslist.application.RevocationAuditDetails;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.exception.UnknownTenantException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.domain.model.RevocationTenantBinding;
import es.in2.issuer.backend.statuslist.domain.model.TenantBindingResolution;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig.RevocationMessagingProperties;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
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

    // F16 (EUD-225 /verify): AD-7 names "alert on anomalous revocation volume" as its own
    // accepted-risk mitigation for the bulk-revocation DoS this queue trigger opens up, but
    // nothing implemented it. A real rate limit / alert threshold is a follow-up decision
    // (documented in tech-debt.md) -- this counter is the minimum viable step so that
    // decision doesn't also require new instrumentation later.
    private static final String METRIC_INSTRUCTION_PROCESSED = "revocation.instruction.processed";
    private static final String TAG_TENANT = "tenant";
    private static final String TAG_ACTOR = "actor";
    private static final String TAG_OUTCOME = "outcome";
    private static final String UNRESOLVED_TENANT_TAG = "unresolved";

    private final RevocationInstructionMessageMapper mapper;
    private final HandleRevocationInstructionWorkflow workflow;
    private final RevocationInstructionErrorClassifier errorClassifier;
    private final TenantRegistryService tenantRegistryService;
    private final RevocationMessagingProperties messagingProperties;
    private final MeterRegistry meterRegistry;

    @RabbitListener(queues = RevocationMessagingConfig.QUEUE_NAME, containerFactory = "revocationListenerContainerFactory")
    public void onMessage(RevocationInstructionMessage message,
                          @Header(value = AmqpHeaders.MESSAGE_ID, required = false) String amqpMessageIdProperty) {
        String processId = UUID.randomUUID().toString();
        // Visible to the catch block below (F16): a failure occurring before the tenant is
        // even resolved (e.g. a malformed message) has no tenant to tag the metric with.
        String contextTenant = null;
        try {
            RevocationInstruction instruction = mapper.toDomain(message, amqpMessageIdProperty, Instant.now());
            log.info("processId={} action=onMessage status=received messageId={} issuanceId={}",
                    processId, logSafe(instruction.messageId()), instruction.issuanceId());

            // F12 (EUD-225 /verify): the RAW message-declared tenantId feeds the mismatch
            // comparison itself (RevocationTenantBinding.resolve) -- environment-suffix
            // stripping must never touch either side of that comparison, or
            // tenant-binding=prh + message tenantId=prh-stg would be silently ACCEPTED
            // instead of rejected (AC-12, fail-open), and tenant-binding=prh-stg + message
            // tenantId=prh-stg (identical strings) would produce a spurious Mismatch
            // (only one side stripped). F5's stripping is applied below instead, only when
            // deriving the tenant actually used for the tenant_registry lookup -- mirroring
            // TenantDomainWebFilter's own originalTenant/resolvedTenant split (lines 162-174).
            RevocationTenantBinding binding = messagingProperties.toRevocationTenantBinding();
            TenantBindingResolution resolution = binding.resolve(instruction.tenantId());

            // The compiler enforces exhaustiveness here (NFR-S-225-07): a fifth,
            // silently-inferred case cannot be added without every switch site like this
            // one failing to compile.
            contextTenant = switch (resolution) {
                case TenantBindingResolution.FromMessage r -> TenantIdentifiers.stripEnvSuffix(r.tenantId());
                case TenantBindingResolution.FromDeployment r -> TenantIdentifiers.stripEnvSuffix(r.tenantId());
                // Never the discordant value from the message: the only tenant legitimate
                // to trace against here is the one this deployment actually declared. Not
                // stripped either -- the registry lookup never runs on this branch (see
                // buildPipeline), this is only what gets written into the Reactor context.
                case TenantBindingResolution.Mismatch r -> r.configured();
                case TenantBindingResolution.Unresolved r -> null;
            };

            if (resolution instanceof TenantBindingResolution.Unresolved) {
                // AC-13 invariant: neither the message nor the deployment declared a
                // tenant. Never inferred — permanent error, no reintentos.
                throw new InvalidRevocationInstructionException(
                        "Revocation instruction has no resolvable tenant: no tenantId in the message "
                                + "and no tenant-binding configured for this deployment");
            }
            validateTenantFormat(contextTenant);

            buildPipeline(processId, instruction, resolution, contextTenant)
                    .timeout(PROCESSING_TIMEOUT)
                    .block();

            log.info("processId={} action=onMessage status=ack messageId={}", processId, logSafe(instruction.messageId()));
            recordProcessed(contextTenant, "success");
        } catch (RuntimeException e) {
            handleFailure(processId, contextTenant, e);
        } finally {
            // F7 (EUD-225 /verify): the AMQP container thread is pooled and reused across
            // deliveries for the lifetime of the container -- clearing MDC here prevents any
            // correlation/tenant context set while processing this message (traceId/spanId/
            // tenantDomain, via Reactor's automatic context propagation across the
            // buildPipeline().block() boundary) from leaking into the next delivery handled
            // by the same thread.
            MDC.clear();
        }
    }

    /**
     * Sanitizes a third-party value (messageId, exception text) before it reaches a log
     * line (F1, EUD-225 {@code /verify}) — the raw value is still what flows into the
     * mapper, the workflow and the inbox; this is only for what ends up in a log sink.
     */
    private static String logSafe(String value) {
        return RevocationAuditDetails.sanitize(value, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH);
    }

    private Mono<Void> buildPipeline(String processId, RevocationInstruction instruction,
                                     TenantBindingResolution resolution, String contextTenant) {
        // A Mismatch is rejected by the workflow itself (with its own audit trail) without
        // ever needing the tenant_registry lookup: the discordance is already the failure.
        if (resolution instanceof TenantBindingResolution.Mismatch) {
            return workflow.handleRevocationInstruction(processId, instruction, resolution)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, contextTenant));
        }

        // F2 (EUD-225 /verify): validate the candidate tenant against the registry BEFORE
        // writing it into the Reactor context -- same order as TenantDomainWebFilter (validate
        // first, contextWrite after). The registry lookup itself must never run under the
        // search_path of the very tenant it exists to authorize.
        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(activeSchemas -> {
                    if (!activeSchemas.contains(contextTenant)) {
                        return Mono.<Void>error(new UnknownTenantException(contextTenant));
                    }
                    return workflow.handleRevocationInstruction(processId, instruction, resolution)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, contextTenant));
                });
    }

    private void validateTenantFormat(String tenantId) {
        if (!TENANT_NAME_PATTERN.matcher(tenantId).matches()) {
            throw new InvalidRevocationInstructionException("Revocation instruction tenantId has an invalid format: " + tenantId);
        }
    }

    private void handleFailure(String processId, String contextTenant, RuntimeException error) {
        Throwable cause = Exceptions.unwrap(error);

        if (errorClassifier.isRetryable(cause)) {
            log.warn("processId={} action=onMessage status=retryable error={}", processId, logSafe(cause.toString()));
            recordProcessed(contextTenant, "retryable");
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            throw new IllegalStateException(cause);
        }

        log.warn("processId={} action=onMessage status=permanent error={}", processId, logSafe(cause.toString()));
        recordProcessed(contextTenant, "permanent");
        throw new AmqpRejectAndDontRequeueException(
                "Permanent revocation instruction failure: " + logSafe(cause.getMessage()), cause);
    }

    /**
     * F16 (EUD-225 {@code /verify}): raw material for a future volume-anomaly alert
     * (AD-7 names this as its own accepted-risk mitigation, not yet implemented -- see
     * {@code tech-debt.md}). {@code tenant} is deliberately the already-resolved,
     * registry-validated {@code contextTenant} (or a fixed placeholder when none was ever
     * resolved) -- never raw message content, which would let a forged {@code tenantId}
     * blow up this metric's label cardinality.
     */
    private void recordProcessed(String contextTenant, String outcome) {
        meterRegistry.counter(METRIC_INSTRUCTION_PROCESSED,
                TAG_TENANT, contextTenant != null ? contextTenant : UNRESOLVED_TENANT_TAG,
                TAG_ACTOR, RevocationWorkflow.ACTOR_REVOCATION_INSTRUCTION,
                TAG_OUTCOME, outcome
        ).increment();
    }
}
