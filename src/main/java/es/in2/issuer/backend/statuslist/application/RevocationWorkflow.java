package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
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

    private final StatusListProvider statusListProvider;
    private final AccessTokenService accessTokenService;
    private final StatusListPdpService statusListPdpService;
    private final IssuanceService issuanceService;
    private final EmailService emailService;
    private final AuditService auditService;

    private record RevocationContext(String token, Issuance issuance) { }

    @FunctionalInterface
    private interface RevocationValidator {
        Mono<Void> validate(String processId, String token, Issuance issuance);
    }

    @Observed(name = "revocation.revoke", contextualName = "revocation-revoke")
    public Mono<Void> revoke(String processId, String bearerToken, String issuanceId, String reason, String publicIssuerBaseUrl) {
        return revokeInternal(
                processId,
                bearerToken,
                issuanceId,
                reason,
                statusListPdpService::validateRevokeCredential,
                "revokeCredential",
                publicIssuerBaseUrl
        );
    }

    @Observed(name = "revocation.revoke-system", contextualName = "revocation-revoke-system")
    public Mono<Void> revokeSystem(String processId, String bearerToken, String issuanceId, String reason, String publicIssuerBaseUrl) {
        return revokeInternal(
                processId,
                bearerToken,
                issuanceId,
                reason,
                (pid, token, issuance) -> statusListPdpService.validateRevokeCredentialSystem(pid, issuance),
                "revokeSystemCredential",
                publicIssuerBaseUrl
        );
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
                                    String processId, String action) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "attempted", null));
            details.put("processId", processId);
            details.put("action", action);
            auditService.auditAttempted(EVENT_ATTEMPTED, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditAttemptedFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private void safeAuditSuccess(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "success", null));
            details.put("processId", processId);
            details.put("action", action);
            auditService.auditSuccess(EVENT_SUCCESS, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditSuccessFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private void safeAuditFailure(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action, Throwable error) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            String errorType = categorizeError(error);
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "failure", errorType));
            details.put("processId", processId);
            details.put("action", action);
            auditService.auditFailure(EVENT_FAILED, actor, errorType, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditFailureFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
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
            String bearerToken,
            String issuanceId,
            String reason,
            RevocationValidator validator,
            String action,
            String publicIssuerBaseUrl
    ) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");

        AtomicReference<String> actorRef = new AtomicReference<>(UNKNOWN_ACTOR);
        AtomicReference<Issuance> issuanceRef = new AtomicReference<>();

        return resolveActor()
                .doOnNext(actorRef::set)
                .flatMap(actor ->
                        accessTokenService.getCleanBearerToken(bearerToken)
                                .doFirst(() -> log.info(
                                        "processId={} action={} status=started issuanceId={}",
                                        processId, action, issuanceId
                                ))
                                .flatMap(token ->
                                        issuanceService.getIssuanceById(issuanceId)
                                                .switchIfEmpty(Mono.defer(() -> {
                                                    safeAuditAttempted(actor, null, issuanceId, reason, processId, action);
                                                    return Mono.<Issuance>error(new IssuanceNotFoundException(
                                                            "No issuance found for issuanceId: " + issuanceId));
                                                }))
                                                .doOnSuccess(p -> log.debug(
                                                        "processId={} action={} step=issuanceLoaded issuanceId={} credentialStatus={}",
                                                        processId, action, issuanceId, p != null ? p.getCredentialStatus() : null
                                                ))
                                                .doOnNext(issuanceRef::set)
                                                .flatMap(issuance -> {
                                                    safeAuditAttempted(actor, issuance, issuanceId, reason, processId, action);
                                                    return validator.validate(processId, token, issuance)
                                                            .doOnSuccess(v -> log.info(
                                                                    "processId={} action={} step=validationPassed issuanceId={}",
                                                                    processId, action, issuanceId
                                                            ))
                                                            .thenReturn(new RevocationContext(token, issuance));
                                                })
                                )
                )
                .flatMap(ctx ->
                        statusListProvider.revoke(issuanceId, ctx.token, publicIssuerBaseUrl)
                                .then(issuanceService.updateIssuanceStatusToRevoked(ctx.issuance)
                                        .doOnSuccess(v -> log.info(
                                                "processId={} action={} step=issuanceUpdated issuanceId={}",
                                                processId, action, issuanceId
                                        ))
                                )
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
                                                processId, action, issuanceId, REVOKED
                                        ))
                                        .onErrorResume(e -> {
                                            log.warn(
                                                    "processId={} action={} step=emailNotificationFailed issuanceId={} error={}",
                                                    processId, action, issuanceId, e.toString()
                                            );
                                            return Mono.empty();
                                        })
                                )
                )
                .doOnSuccess(v -> {
                    log.info("processId={} action={} status=completed issuanceId={}",
                            processId, action, issuanceId);
                    // Post-commit: the revocation is already consumed at this point, so a logging
                    // failure inside safeAuditSuccess must never surface as an error here (ES-04).
                    safeAuditSuccess(actorRef.get(), issuanceRef.get(), issuanceId, reason, processId, action);
                })
                .doOnError(e -> {
                    log.warn(
                            "processId={} action={} status=failed issuanceId={} error={}",
                            processId, action, issuanceId, e.toString()
                    );
                    safeAuditFailure(actorRef.get(), issuanceRef.get(), issuanceId, reason, processId, action, e);
                });
    }
}
