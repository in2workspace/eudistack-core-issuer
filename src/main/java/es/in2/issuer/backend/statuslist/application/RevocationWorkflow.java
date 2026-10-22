package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.statuslist.domain.audit.RevocationAuditEvents;
import es.in2.issuer.backend.statuslist.domain.audit.RevocationAuditEvents.Origin;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.REVOKED;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationWorkflow {

    private static final String EVENT_ATTEMPTED = "credential.revoke.attempted";
    private static final String EVENT_SUCCESS = "credential.revoked";
    private static final String EVENT_FAILED = "credential.revoke.failed";
    private static final String UNKNOWN_ACTOR = "unknown";

    /** Actor of the system-triggered path fed by the OID4VCI credential_deleted notification. */
    public static final String ACTOR_OID4VCI_NOTIFICATION = "system:oid4vci-notification";

    /** Actor of the system-triggered path fed by the revocation-instruction message queue (EUD-225). */
    public static final String ACTOR_REVOCATION_INSTRUCTION = "system:revocation-instruction";

    private final StatusListProvider statusListProvider;
    private final AccessTokenService accessTokenService;
    private final StatusListPdpService statusListPdpService;
    private final IssuanceService issuanceService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final AuditTrailPort auditTrail;
    private final TransactionalOperator transactionalOperator;

    private record RevocationContext(String token, Issuance issuance) { }

    @FunctionalInterface
    private interface RevocationValidator {
        Mono<Void> validate(String processId, String token, Issuance issuance);
    }

    /**
     * Operator-triggered revocation (portal). The actor is resolved from the reactive
     * security context and a caller token is required, cleaned, and propagated to signing.
     */
    @Observed(name = "revocation.revoke", contextualName = "revocation-revoke")
    public Mono<Void> revoke(String processId, String bearerToken, String issuanceId, String reason, String publicIssuerBaseUrl) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");
        return auditTrail.withCorrelationId(processId, resolveActor()
                .flatMap(actor ->
                        accessTokenService.getCleanBearerToken(bearerToken)
                                .flatMap(token -> revokeInternal(
                                        processId,
                                        Optional.of(token),
                                        issuanceId,
                                        reason,
                                        actor,
                                        (pid, t, issuance) -> statusListPdpService.validateRevokeCredential(pid, t, issuance),
                                        "revokeCredential",
                                        publicIssuerBaseUrl,
                                        null,
                                        Optional.of(Origin.REQUEST)
                                ))
                ));
    }

    /**
     * System-triggered revocation (no HTTP caller behind it: OID4VCI notification, revocation
     * instruction queue). There is no caller token to propagate (AD-1: the token was vestigial
     * downstream and is never used to authorize or sign); the actor is declared explicitly by
     * the caller instead of being resolved from a security context that does not exist (AD-3).
     */
    @Observed(name = "revocation.revoke-system", contextualName = "revocation-revoke-system")
    public Mono<Void> revokeSystem(String processId, String issuanceId, String reason, String actor, String publicIssuerBaseUrl) {
        return revokeSystem(processId, issuanceId, reason, actor, publicIssuerBaseUrl, null);
    }

    /**
     * @param tenantSource where the effective tenant of this system trigger came from
     *                     (e.g. {@code "deployment"} for AD-8's single-tenant binding,
     *                     EUD-225 AC-11), recorded in the audit trail when present.
     *                     {@code null} when the trigger has no such concept (e.g. the
     *                     OID4VCI notification path).
     */
    public Mono<Void> revokeSystem(String processId, String issuanceId, String reason, String actor,
                                   String publicIssuerBaseUrl, String tenantSource) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(actor, "actor");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");
        return revokeInternal(
                processId,
                Optional.empty(),
                issuanceId,
                reason,
                actor,
                (pid, t, issuance) -> statusListPdpService.validateRevokeCredentialSystem(pid, issuance),
                "revokeSystemCredential",
                publicIssuerBaseUrl,
                tenantSource,
                auditOriginOf(actor)
        );
    }

    /** Only a revocation caused by a wallet notification has an origin in the catalogue besides a request. */
    private static Optional<Origin> auditOriginOf(String actor) {
        return ACTOR_OID4VCI_NOTIFICATION.equals(actor) ? Optional.of(Origin.WALLET_NOTIFICATION) : Optional.empty();
    }

    private Mono<String> resolveActor() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated() && auth.getName() != null)
                .map(Authentication::getName)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Revocation audit: operator identity not resolvable from security context");
                    return Mono.just(UNKNOWN_ACTOR);
                }));
    }

    private void safeAuditAttempted(String actor, Issuance issuance, String issuanceId, String reason,
                                    String processId, String action, String tenantSource) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "attempted", null));
            details.put("processId", processId);
            details.put("workflowAction", action);
            putTenantSourceIfPresent(details, tenantSource);
            auditService.auditAttempted(EVENT_ATTEMPTED, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditAttemptedFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private void safeAuditSuccess(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action, String tenantSource) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "success", null));
            details.put("processId", processId);
            details.put("workflowAction", action);
            putTenantSourceIfPresent(details, tenantSource);
            auditService.auditSuccess(EVENT_SUCCESS, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditSuccessFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private void safeAuditFailure(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action, Throwable error, String tenantSource) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            String errorType = categorizeError(error);
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "failure", errorType));
            details.put("processId", processId);
            details.put("workflowAction", action);
            putTenantSourceIfPresent(details, tenantSource);
            auditService.auditFailure(EVENT_FAILED, actor, errorType, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditFailureFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private static void putTenantSourceIfPresent(Map<String, Object> details, String tenantSource) {
        if (tenantSource != null && !tenantSource.isBlank()) {
            details.put("tenantSource", tenantSource);
        }
    }

    private static String categorizeError(Throwable error) {
        if (error instanceof IssuanceNotFoundException) {
            return "issuance_not_found";
        }
        if (error instanceof InvalidStatusException) {
            return "invalid_status";
        }
        if (error instanceof UnauthorizedRoleException) {
            return "unauthorized_role";
        }
        if (error instanceof TenantMismatchException) {
            return "tenant_mismatch";
        }
        return error.getClass().getSimpleName();
    }

    private Mono<Void> revokeInternal(
            String processId,
            Optional<String> token,
            String issuanceId,
            String reason,
            String actor,
            RevocationValidator validator,
            String action,
            String publicIssuerBaseUrl,
            String tenantSource,
            Optional<Origin> auditOrigin
    ) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(actor, "actor");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");

        String tokenValue = token.orElse(null);
        AtomicReference<Issuance> issuanceRef = new AtomicReference<>();
        AtomicBoolean statusListFailed = new AtomicBoolean();
        // issuanceId is boundary-validated as a well-formed UUID on both callers (the operator
        // DTO's @Pattern and the queue mapper's UUID.fromString) by the time it reaches here,
        // but this method's log statements are a shared sink for both paths. quoteIfNeeded
        // (for logging only -- the real lookups/audit calls below keep the raw value) both
        // strips control characters and quotes/escapes an embedded '=' or '"', unlike plain
        // sanitize() alone (CodeQL java/log-injection, EUD-225 PR review -- see the note on
        // RevocationAuditDetails.quoteIfNeeded).
        String safeIssuanceId = RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH);

        Mono<Void> revocation = Mono.defer(() -> {
                    log.info("processId={} action={} status=started issuanceId={}", processId, action, safeIssuanceId);
                    return issuanceService.getIssuanceById(issuanceId)
                            .switchIfEmpty(Mono.defer(() -> {
                                safeAuditAttempted(actor, null, issuanceId, reason, processId, action, tenantSource);
                                return Mono.<Issuance>error(new IssuanceNotFoundException(
                                        "No issuance found for issuanceId: " + issuanceId));
                            }))
                            .doOnSuccess(p -> log.debug(
                                    "processId={} action={} step=issuanceLoaded issuanceId={} credentialStatus={}",
                                    processId, action, safeIssuanceId, p != null ? p.getCredentialStatus() : null
                            ))
                            .doOnNext(issuanceRef::set)
                            .flatMap(issuance -> {
                                safeAuditAttempted(actor, issuance, issuanceId, reason, processId, action, tenantSource);
                                return validator.validate(processId, tokenValue, issuance)
                                        .doOnSuccess(v -> log.info(
                                                "processId={} action={} step=validationPassed issuanceId={}",
                                                processId, action, safeIssuanceId
                                        ))
                                        .thenReturn(new RevocationContext(tokenValue, issuance));
                            });
                })
                .flatMap(ctx ->
                        statusListProvider.revoke(issuanceId, ctx.token, publicIssuerBaseUrl)
                                .doOnError(e -> statusListFailed.set(!(e instanceof StatusListIndexNotFoundException)))
                                .then(transactionalOperator.transactional(
                                        issuanceService.updateIssuanceStatusToRevoked(ctx.issuance)
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action={} step=issuanceUpdated issuanceId={}",
                                                        processId, action, safeIssuanceId
                                                ))
                                                .then(Mono.defer(() -> stageApplied(
                                                        auditOrigin, issuanceId, reason, ctx.issuance)))
                                ))
                                .then(issuanceService.extractCredentialId(ctx.issuance)
                                        .defaultIfEmpty(issuanceId)
                                        .flatMap(credentialId -> emailService.sendCredentialStatusChangeNotification(
                                                ctx.issuance.getEmail(),
                                                credentialId,
                                                ctx.issuance.getCredentialType(),
                                                REVOKED
                                        ))
                                        .doOnSuccess(v -> log.debug(
                                                "processId={} action={} step=emailNotificationTriggered issuanceId={} newStatus={}",
                                                processId, action, safeIssuanceId, REVOKED
                                        ))
                                        .onErrorResume(e -> {
                                            log.warn(
                                                    "processId={} action={} step=emailNotificationFailed issuanceId={} error={}",
                                                    processId, action, safeIssuanceId, e.toString()
                                            );
                                            return Mono.empty();
                                        })
                                )
                )
                .doOnSuccess(v -> {
                    log.info("processId={} action={} status=completed issuanceId={}",
                            processId, action, safeIssuanceId);
                    // Post-commit: the revocation is already consumed at this point, so a logging
                    // failure inside safeAuditSuccess must never surface as an error here (ES-04).
                    safeAuditSuccess(actor, issuanceRef.get(), issuanceId, reason, processId, action, tenantSource);
                })
                .doOnError(e -> {
                    log.warn(
                            "processId={} action={} status=failed issuanceId={} error={}",
                            processId, action, safeIssuanceId, e.toString()
                    );
                    safeAuditFailure(actor, issuanceRef.get(), issuanceId, reason, processId, action, e, tenantSource);
                });

        return auditTrail.stageOnError(revocation,
                error -> refusalOf(error, auditOrigin, issuanceId, reason, issuanceRef.get(), statusListFailed.get()));
    }

    private Mono<Void> stageApplied(Optional<Origin> auditOrigin, String issuanceId, String reason, Issuance issuance) {
        return auditOrigin
                .map(origin -> auditTrail.stage(RevocationAuditEvents.applied(
                        issuanceId, origin, reason, holderOf(issuance))))
                .orElseGet(Mono::empty);
    }

    /**
     * The catalogue entry for a revocation that was refused, or empty when the failure has no reason in
     * the catalogue (a persistence error, say): the business failure stands and no reason is invented.
     */
    private Optional<AuditEntry> refusalOf(Throwable error, Optional<Origin> auditOrigin, String issuanceId,
                                           String reason, Issuance issuance, boolean statusListFailed) {
        return auditOrigin.flatMap(origin -> catalogueReasonOf(error, issuance, statusListFailed)
                .map(catalogueReason -> RevocationAuditEvents.refused(
                        issuanceId, origin, catalogueReason, reason, holderOf(issuance))));
    }

    private Optional<String> catalogueReasonOf(Throwable error, Issuance issuance, boolean statusListFailed) {
        if (error instanceof IssuanceNotFoundException) {
            return Optional.of("IssuanceNotFound");
        }
        if (error instanceof InvalidStatusException) {
            boolean alreadyRevoked = issuance != null && issuance.getCredentialStatus() == CredentialStatusEnum.REVOKED;
            return Optional.of(alreadyRevoked ? "AlreadyRevoked" : "NotRevocable");
        }
        if (error instanceof UnauthorizedRoleException || error instanceof TenantMismatchException) {
            return Optional.of("PolicyDenied");
        }
        return statusListFailed ? Optional.of("StatusListUnavailable") : Optional.empty();
    }

    /** The holder is only reported once the process was resolved; an unknown process has none to give. */
    private static Holder holderOf(Issuance issuance) {
        return issuance == null ? null : new Holder(null, issuance.getSubject(), issuance.getEmail());
    }
}
