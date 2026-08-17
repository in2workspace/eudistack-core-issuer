package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.statuslist.domain.exception.RevocationInstructionInProgressException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.domain.service.StatusListPublicBaseUrlResolver;
import es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.statuslist.application.RevocationWorkflow.ACTOR_REVOCATION_INSTRUCTION;
import static es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox.ClaimResult.ALREADY_PROCESSED;
import static es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox.ClaimResult.CLAIMED;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

/**
 * Orchestrates a revocation instruction received from the message queue (EUD-225):
 * {@code claim} (AD-4 idempotency) → resolve the public base URL the target status
 * list was signed against (AD-2) → {@link RevocationWorkflow#revokeSystem} → close
 * the inbox. Translates "credential no longer revocable" into a silent no-op with
 * its own audit trail (AC-06), which is a domain result for this Story, not an
 * error — the {@code RevocationWorkflow.revokeSystem} call it wraps still reports
 * its own {@code credential.revoke.failed} event first, this workflow only adds
 * the disambiguating {@code credential.revoke.skipped} on top.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HandleRevocationInstructionWorkflow {

    private static final String EVENT_SKIPPED = "credential.revoke.skipped";
    private static final String OUTCOME_NOOP = "noop";
    private static final String RESOURCE_TYPE_CREDENTIAL = "credential";

    private final RevocationInstructionInbox inbox;
    private final StatusListPublicBaseUrlResolver publicBaseUrlResolver;
    private final RevocationWorkflow revocationWorkflow;
    private final AuditService auditService;

    @Observed(name = "revocation.handle-instruction", contextualName = "revocation-handle-instruction")
    public Mono<Void> handleRevocationInstruction(String processId, RevocationInstruction instruction) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(instruction, "instruction");

        return inbox.claim(instruction.messageId(), instruction.issuanceId())
                .flatMap(claimResult -> {
                    if (claimResult == ALREADY_PROCESSED) {
                        log.info("processId={} action=handleRevocationInstruction status=alreadyProcessed messageId={}",
                                processId, instruction.messageId());
                        return Mono.empty();
                    }
                    if (claimResult == CLAIMED) {
                        return processClaimed(processId, instruction);
                    }
                    // IN_PROGRESS: another delivery of the same messageId owns an unexpired
                    // claim. Retryable — the caller (listener) redelivers with backoff.
                    return Mono.error(new RevocationInstructionInProgressException(instruction.messageId()));
                });
    }

    private Mono<Void> processClaimed(String processId, RevocationInstruction instruction) {
        return publicBaseUrlResolver.resolve(instruction.issuanceId())
                .flatMap(publicIssuerBaseUrl -> revocationWorkflow.revokeSystem(
                                processId,
                                instruction.issuanceId(),
                                instruction.reason(),
                                ACTOR_REVOCATION_INSTRUCTION,
                                publicIssuerBaseUrl
                        )
                        // Mono.defer: markProcessed() must not even be constructed unless
                        // revokeSystem actually completed — a plain .then(inbox.markProcessed(...))
                        // evaluates its argument eagerly at chain-assembly time, before the
                        // preceding Mono is subscribed to.
                        .then(Mono.defer(() -> inbox.markProcessed(instruction.messageId())))
                        .doOnSuccess(v -> log.info(
                                "processId={} action=handleRevocationInstruction status=processed messageId={} issuanceId={}",
                                processId, instruction.messageId(), instruction.issuanceId()
                        ))
                )
                .onErrorResume(
                        HandleRevocationInstructionWorkflow::isNotRevocable,
                        e -> skipAsNoop(processId, instruction, e)
                );
    }

    private static boolean isNotRevocable(Throwable e) {
        return e instanceof InvalidStatusException || e instanceof InvalidCredentialStatusTransitionException;
    }

    private Mono<Void> skipAsNoop(String processId, RevocationInstruction instruction, Throwable cause) {
        log.info(
                "processId={} action=handleRevocationInstruction status=noop messageId={} issuanceId={} cause={}",
                processId, instruction.messageId(), instruction.issuanceId(), cause.toString()
        );
        safeAuditSkipped(instruction, processId);
        return inbox.markSkipped(instruction.messageId());
    }

    private void safeAuditSkipped(RevocationInstruction instruction, String processId) {
        try {
            Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                    ACTOR_REVOCATION_INSTRUCTION, null, instruction.issuanceId(), instruction.reason(), OUTCOME_NOOP, null);
            auditService.auditSuccess(EVENT_SKIPPED, ACTOR_REVOCATION_INSTRUCTION, RESOURCE_TYPE_CREDENTIAL,
                    instruction.issuanceId(), details);
        } catch (Exception e) {
            log.warn("processId={} action=handleRevocationInstruction step=auditSkippedFailed messageId={} error={}",
                    processId, instruction.messageId(), e.toString());
        }
    }
}
