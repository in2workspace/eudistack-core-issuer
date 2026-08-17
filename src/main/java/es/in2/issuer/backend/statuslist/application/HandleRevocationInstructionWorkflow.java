package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.statuslist.domain.exception.RevocationInstructionInProgressException;
import es.in2.issuer.backend.statuslist.domain.exception.TenantBindingMismatchException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.domain.model.TenantBindingResolution;
import es.in2.issuer.backend.statuslist.domain.service.StatusListPublicBaseUrlResolver;
import es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
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
    private static final String EVENT_FAILED = "credential.revoke.failed";
    private static final String OUTCOME_NOOP = "noop";
    private static final String RESOURCE_TYPE_CREDENTIAL = "credential";
    private static final String ERROR_TYPE_TENANT_BINDING_MISMATCH = "tenant_binding_mismatch";
    private static final String TENANT_SOURCE_DEPLOYMENT = "deployment";
    private static final String TENANT_SOURCE_MESSAGE = "message";

    private final RevocationInstructionInbox inbox;
    private final StatusListPublicBaseUrlResolver publicBaseUrlResolver;
    private final RevocationWorkflow revocationWorkflow;
    private final AuditService auditService;

    /**
     * @param tenantResolution AD-8's tenant binding outcome for this instruction. A
     *                         {@link TenantBindingResolution.Mismatch} is rejected here,
     *                         with its own audit trail, <b>before</b> claiming the inbox
     *                         (a message that will never be processed must not consume a
     *                         {@code messageId}). Otherwise, {@code tenantSource} is
     *                         forwarded to {@link RevocationWorkflow#revokeSystem} so
     *                         AC-11's audit requirement (the trace records whether the
     *                         effective tenant came from the deployment or the message)
     *                         is met on the very same {@code credential.revoke.*} events,
     *                         not a duplicate one.
     */
    @Observed(name = "revocation.handle-instruction", contextualName = "revocation-handle-instruction")
    public Mono<Void> handleRevocationInstruction(String processId, RevocationInstruction instruction,
                                                  TenantBindingResolution tenantResolution) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(instruction, "instruction");
        requireNonNullParam(tenantResolution, "tenantResolution");

        if (tenantResolution instanceof TenantBindingResolution.Mismatch mismatch) {
            return rejectMismatch(processId, instruction, mismatch);
        }

        String tenantSource = (tenantResolution instanceof TenantBindingResolution.FromDeployment)
                ? TENANT_SOURCE_DEPLOYMENT
                : TENANT_SOURCE_MESSAGE;

        return inbox.claim(instruction.messageId(), instruction.issuanceId())
                .flatMap(claimResult -> {
                    if (claimResult == ALREADY_PROCESSED) {
                        log.info("processId={} action=handleRevocationInstruction status=alreadyProcessed messageId={}",
                                processId, logSafe(instruction.messageId()));
                        return Mono.empty();
                    }
                    if (claimResult == CLAIMED) {
                        return processClaimed(processId, instruction, tenantSource);
                    }
                    // IN_PROGRESS: another delivery of the same messageId owns an unexpired
                    // claim. Retryable — the caller (listener) redelivers with backoff.
                    return Mono.error(new RevocationInstructionInProgressException(logSafe(instruction.messageId())));
                });
    }

    /**
     * Sanitizes a third-party value (declared tenantId, messageId, exception text) before
     * it reaches a log line or an audit detail (F1, EUD-225 {@code /verify}) — never used
     * for the functional inbox operations ({@code claim}/{@code markProcessed}/
     * {@code markSkipped}/{@code release}), which must keep the exact original value.
     */
    private static String logSafe(String value) {
        return RevocationAuditDetails.sanitize(value, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH);
    }

    /**
     * A discordant tenant is rejected without ever reclaiming the inbox: the discordance
     * itself is evidence the publisher's model of the world does not match this
     * deployment's, so the {@code issuanceId} it carries is suspect too — the instruction
     * is stopped and made visible, not attributed to the configured tenant regardless.
     */
    private Mono<Void> rejectMismatch(String processId, RevocationInstruction instruction,
                                      TenantBindingResolution.Mismatch mismatch) {
        String declaredTenant = logSafe(mismatch.declaredInMessage());
        log.warn(
                "processId={} action=handleRevocationInstruction status=tenantBindingMismatch "
                        + "messageId={} declaredInMessage={} configured={}",
                processId, logSafe(instruction.messageId()), declaredTenant, mismatch.configured()
        );
        try {
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    ACTOR_REVOCATION_INSTRUCTION, null, instruction.issuanceId(), instruction.reason(),
                    "failure", ERROR_TYPE_TENANT_BINDING_MISMATCH));
            details.put("declaredTenant", declaredTenant);
            auditService.auditFailure(EVENT_FAILED, ACTOR_REVOCATION_INSTRUCTION, ERROR_TYPE_TENANT_BINDING_MISMATCH, details);
        } catch (Exception e) {
            log.warn("processId={} action=handleRevocationInstruction step=auditMismatchFailed messageId={} error={}",
                    processId, logSafe(instruction.messageId()), logSafe(e.toString()));
        }
        return Mono.error(new TenantBindingMismatchException(mismatch.declaredInMessage(), mismatch.configured()));
    }

    private Mono<Void> processClaimed(String processId, RevocationInstruction instruction, String tenantSource) {
        return publicBaseUrlResolver.resolve(instruction.issuanceId())
                .flatMap(publicIssuerBaseUrl -> revocationWorkflow.revokeSystem(
                                processId,
                                instruction.issuanceId(),
                                instruction.reason(),
                                ACTOR_REVOCATION_INSTRUCTION,
                                publicIssuerBaseUrl,
                                tenantSource
                        )
                        // Mono.defer: markProcessed() must not even be constructed unless
                        // revokeSystem actually completed — a plain .then(inbox.markProcessed(...))
                        // evaluates its argument eagerly at chain-assembly time, before the
                        // preceding Mono is subscribed to.
                        .then(Mono.defer(() -> inbox.markProcessed(instruction.messageId())))
                        .doOnSuccess(v -> log.info(
                                "processId={} action=handleRevocationInstruction status=processed messageId={} issuanceId={}",
                                processId, logSafe(instruction.messageId()), instruction.issuanceId()
                        ))
                )
                .onErrorResume(e -> isNotRevocable(e)
                        ? skipAsNoop(processId, instruction, e)
                        : releaseClaimThenPropagate(processId, instruction, e));
    }

    /**
     * A failure that is neither success nor "no longer revocable" leaves the claim
     * {@code IN_PROGRESS}. Releasing it here lets the very next attempt — an in-process
     * retry (AD-5) or a genuine redelivery — re-claim immediately instead of finding its
     * own abandoned attempt still "in progress" for up to the full lease window
     * (NFR-S-225-04), which would otherwise make every retryable failure (ES-04) look
     * identical to EC-03 and silently defeat AC-09's recovery guarantee.
     */
    private Mono<Void> releaseClaimThenPropagate(String processId, RevocationInstruction instruction, Throwable error) {
        return inbox.release(instruction.messageId())
                .doOnSuccess(v -> log.debug(
                        "processId={} action=handleRevocationInstruction step=claimReleased messageId={}",
                        processId, logSafe(instruction.messageId())))
                .onErrorResume(releaseError -> {
                    log.warn(
                            "processId={} action=handleRevocationInstruction step=claimReleaseFailed messageId={} error={}",
                            processId, logSafe(instruction.messageId()), logSafe(releaseError.toString()));
                    return Mono.empty();
                })
                .then(Mono.error(error));
    }

    private static boolean isNotRevocable(Throwable e) {
        return e instanceof InvalidStatusException || e instanceof InvalidCredentialStatusTransitionException;
    }

    private Mono<Void> skipAsNoop(String processId, RevocationInstruction instruction, Throwable cause) {
        log.info(
                "processId={} action=handleRevocationInstruction status=noop messageId={} issuanceId={} cause={}",
                processId, logSafe(instruction.messageId()), instruction.issuanceId(), logSafe(cause.toString())
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
                    processId, logSafe(instruction.messageId()), logSafe(e.toString()));
        }
    }
}
