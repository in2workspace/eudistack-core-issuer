package es.in2.issuer.backend.statuslist.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import es.in2.issuer.backend.statuslist.domain.exception.AlreadyRevokedException;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationRequestException;
import es.in2.issuer.backend.statuslist.domain.exception.NotRevocableException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListUnavailableException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationRequestViolation;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

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
    private static final String ANONYMOUS_ACTOR = "anonymous";
    private static final String ACTION_REVOKE_ISSUANCE = "revokeIssuance";
    private static final String ERROR_TYPE_BAD_REQUEST = "BAD_REQUEST";

    /** Token claims naming a requester whose principal is not an email: a system, or an SD-JWT attestation. */
    private static final List<String> REQUESTER_CLAIMS = List.of("sub", "client_id", "azp", "jti");

    /**
     * Where each attestation type keeps the holder's document, in {@code credential_data_set}
     * (AD-6). A type without any of them, like a machine attestation, leaves the field empty.
     */
    private static final List<String> HOLDER_DOCUMENT_POINTERS = List.of(
            "/document_number",
            "/personal_administrative_number",
            "/mandate/mandatee/employeeId",
            "/credentialSubject/mandate/mandatee/employeeId",
            "/vc/credentialSubject/mandate/mandatee/employeeId");

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
    private final JWTService jwtService;
    private final ObjectMapper objectMapper;

    private record RevocationContext(String token, Issuance issuance) { }

    /** The caller of the contract's route, as the audit trail names them (AC-10). */
    private record Requester(String actor, String organization) { }

    /**
     * What differs between the entry points of a revocation.
     *
     * @param action       name of the workflow action in logs and audit
     * @param validator    decides whether this process can be revoked by this caller
     * @param whenMissing  decided before answering that the process does not exist
     * @param markFailure  translates a failure marking the list and committing the process
     * @param auditContext extra fields of every audit event of this entry point
     * @param traceHolder  whether the outcome events name the holder in clear (AC-13). Not for the
     *                     system triggers, which EUD-247 leaves out and whose trace carries no
     *                     personal data (EUD-225 AC-02)
     */
    private record RevocationPath(String action,
                                  RevocationValidator validator,
                                  Mono<Void> whenMissing,
                                  UnaryOperator<Throwable> markFailure,
                                  Map<String, Object> auditContext,
                                  boolean traceHolder) { }

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
        return resolveActor()
                .flatMap(actor ->
                        accessTokenService.getCleanBearerToken(bearerToken)
                                .flatMap(token -> revokeInternal(
                                        processId,
                                        Optional.of(token),
                                        issuanceId,
                                        reason,
                                        actor,
                                        publicIssuerBaseUrl,
                                        new RevocationPath(
                                                "revokeCredential",
                                                (pid, t, issuance) -> statusListPdpService.validateRevokeCredential(pid, t, issuance),
                                                Mono.empty(),
                                                UnaryOperator.identity(),
                                                Map.of(),
                                                true
                                        )
                                ))
                );
    }

    /**
     * Revocation under the contract of EUD-247, for operators and systems alike. Rejections carry
     * the contract's codes, an id out of scope reads like one that does not exist, and a failure
     * marking the list leaves everything as it was.
     */
    @Observed(name = "revocation.revoke-issuance", contextualName = "revocation-revoke-issuance")
    public Mono<Void> revokeIssuance(String processId, String bearerToken, String issuanceId, String reason, String publicIssuerBaseUrl) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");
        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> resolveRequester(bearerToken, token)
                        .flatMap(requester -> {
                            Map<String, Object> auditContext = Map.of("requesterOrganizationId", requester.organization());
                            List<RevocationRequestViolation> violations = RevocationRequestValidator.validate(issuanceId, reason);
                            if (!violations.isEmpty()) {
                                return rejectInvalidRequest(processId, requester.actor(), issuanceId, reason, violations, auditContext);
                            }
                            return revokeInternal(
                                    processId,
                                    Optional.of(token),
                                    issuanceId,
                                    reason,
                                    requester.actor(),
                                    publicIssuerBaseUrl,
                                    new RevocationPath(
                                            ACTION_REVOKE_ISSUANCE,
                                            (pid, t, issuance) -> statusListPdpService.validateRevokeScope(pid, t, issuance)
                                                    .then(Mono.defer(() -> requireRevocable(issuanceId, issuance))),
                                            Mono.defer(() -> statusListPdpService.validateRevokePermission(processId, token)),
                                            error -> toContractFailure(issuanceId, error),
                                            auditContext,
                                            true
                                    )
                            );
                        }));
    }

    private Mono<Void> rejectInvalidRequest(String processId, String actor, String issuanceId, String reason,
                                            List<RevocationRequestViolation> violations, Map<String, Object> auditContext) {
        InvalidRevocationRequestException rejection = new InvalidRevocationRequestException(violations);
        log.info("processId={} action={} status=rejected issuanceId={}", processId, ACTION_REVOKE_ISSUANCE,
                RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH));
        // The audit sink does its own quoting: it gets the value sanitized, not already quoted for a log line.
        safeAuditFailure(actor, null, RevocationAuditDetails.sanitize(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH),
                reason, processId, ACTION_REVOKE_ISSUANCE, rejection, auditContext);
        return Mono.error(rejection);
    }

    private static Mono<Void> requireRevocable(String issuanceId, Issuance issuance) {
        CredentialStatusEnum status = issuance.getCredentialStatus();
        if (status == CredentialStatusEnum.VALID) {
            return Mono.empty();
        }
        if (status == CredentialStatusEnum.REVOKED) {
            return Mono.error(new AlreadyRevokedException(issuanceId));
        }
        return Mono.error(new NotRevocableException("Attestation not revocable in status " + status));
    }

    /**
     * Nothing was committed when this runs. A process that stopped being Valid after the check, as
     * the loser of two simultaneous revocations finds it, gets the code of its current status; an
     * attestation without a position in a list that exists cannot be marked, today or on a retry; a
     * programming error is not something a retry solves; anything else may pass, so the client is
     * told to retry.
     */
    private static Throwable toContractFailure(String issuanceId, Throwable error) {
        if (error instanceof InvalidCredentialStatusTransitionException transition) {
            return transition.getFrom() == CredentialStatusEnum.REVOKED
                    ? new AlreadyRevokedException(issuanceId)
                    : new NotRevocableException("Attestation not revocable in status " + transition.getFrom());
        }
        if (error instanceof StatusListIndexNotFoundException || error instanceof StatusListNotFoundException) {
            return new NotRevocableException("Attestation without a position in a status list");
        }
        if (error instanceof IssuanceNotFoundException
                || error instanceof NullPointerException
                || error instanceof IllegalArgumentException
                || error instanceof ClassCastException) {
            return error;
        }
        return new StatusListUnavailableException("The attestation could not be marked in its status list", error);
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
                publicIssuerBaseUrl,
                new RevocationPath(
                        "revokeSystemCredential",
                        (pid, t, issuance) -> statusListPdpService.validateRevokeCredentialSystem(pid, issuance),
                        Mono.empty(),
                        UnaryOperator.identity(),
                        tenantSource != null && !tenantSource.isBlank() ? Map.of("tenantSource", tenantSource) : Map.of(),
                        false
                )
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

    /**
     * A principal is resolved only from an email in the token, so a system or an SD-JWT attestation
     * arrives as {@code anonymous}: the token's own identifier names them in the trace (AC-10).
     */
    private Mono<Requester> resolveRequester(String bearerToken, String token) {
        Mono<String> organization = accessTokenService.getOrganizationId(bearerToken)
                .onErrorResume(e -> Mono.empty())
                .defaultIfEmpty("");
        return resolveActor()
                .map(actor -> ANONYMOUS_ACTOR.equals(actor) || UNKNOWN_ACTOR.equals(actor)
                        ? actorFromToken(token).orElse(actor)
                        : actor)
                .zipWith(organization, Requester::new);
    }

    private Optional<String> actorFromToken(String token) {
        try {
            Map<String, Object> claims = jwtService.parseJWT(token).getJWTClaimsSet().getClaims();
            return REQUESTER_CLAIMS.stream()
                    .map(claims::get)
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(value -> !value.isBlank())
                    .findFirst();
        } catch (ParseException | RuntimeException e) {
            log.warn("Revocation audit: requester not resolvable from the token: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private Map<String, Object> outcomeContext(RevocationPath path, Issuance issuance) {
        if (!path.traceHolder() || issuance == null) {
            return path.auditContext();
        }
        Map<String, Object> context = new LinkedHashMap<>(path.auditContext());
        try {
            context.putAll(RevocationAuditDetails.holderFields(issuance.getSubject(), issuance.getEmail(), holderDocument(issuance)));
        } catch (RuntimeException e) {
            // Runs after the commit: a problem describing the holder never undoes the answer (AC-12).
            log.warn("Revocation audit: holder not readable for issuanceId={}: {}", issuance.getIssuanceId(), e.getClass().getSimpleName());
        }
        return context;
    }

    private String holderDocument(Issuance issuance) {
        String dataSet = issuance.getCredentialDataSet();
        if (dataSet == null || dataSet.isBlank()) {
            return null;
        }
        try {
            JsonNode credential = objectMapper.readTree(dataSet);
            return HOLDER_DOCUMENT_POINTERS.stream()
                    .map(credential::at)
                    .filter(node -> node.isValueNode() && !node.isNull())
                    .map(JsonNode::asText)
                    .filter(value -> !value.isBlank())
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            // Never fails a revocation: the trace keeps the rest of the holder's data.
            log.warn("Revocation audit: holder document not readable for issuanceId={}: {}",
                    issuance.getIssuanceId(), e.getClass().getSimpleName());
            return null;
        }
    }

    private void safeAuditAttempted(String actor, Issuance issuance, String issuanceId, String reason,
                                    String processId, String action, Map<String, Object> auditContext) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "attempted", null));
            details.put("processId", processId);
            details.put("workflowAction", action);
            details.putAll(auditContext);
            auditService.auditAttempted(EVENT_ATTEMPTED, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditAttemptedFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private void safeAuditSuccess(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action, Map<String, Object> auditContext) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "success", null));
            details.put("processId", processId);
            details.put("workflowAction", action);
            details.putAll(auditContext);
            auditService.auditSuccess(EVENT_SUCCESS, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditSuccessFailed issuanceId={} error={}",
                    processId, action, issuanceId, e.toString());
        }
    }

    private void safeAuditFailure(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action, Throwable error, Map<String, Object> auditContext) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            String errorType = categorizeError(error);
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "failure", errorType));
            details.put("processId", processId);
            details.put("workflowAction", action);
            details.putAll(auditContext);
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
        if (error instanceof InsufficientPermissionException) {
            return "insufficient_permission";
        }
        if (error instanceof AlreadyRevokedException) {
            return "already_revoked";
        }
        if (error instanceof NotRevocableException) {
            return "not_revocable";
        }
        if (error instanceof StatusListUnavailableException) {
            return "status_list_unavailable";
        }
        if (error instanceof InvalidRevocationRequestException) {
            return ERROR_TYPE_BAD_REQUEST;
        }
        return error.getClass().getSimpleName();
    }

    private Mono<Void> revokeInternal(
            String processId,
            Optional<String> token,
            String issuanceId,
            String reason,
            String actor,
            String publicIssuerBaseUrl,
            RevocationPath path
    ) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(actor, "actor");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");

        String tokenValue = token.orElse(null);
        String action = path.action();
        Map<String, Object> auditContext = path.auditContext();
        AtomicReference<Issuance> issuanceRef = new AtomicReference<>();
        // issuanceId is boundary-validated as a well-formed UUID on the contract route, the alias
        // (the DTO's @Pattern) and the queue (the mapper's UUID.fromString), but not on PATCH, and
        // this method's log statements are a shared sink for all of them. quoteIfNeeded
        // (for logging only -- the real lookups/audit calls below keep the raw value) both
        // strips control characters and quotes/escapes an embedded '=' or '"', unlike plain
        // sanitize() alone (CodeQL java/log-injection, EUD-225 PR review -- see the note on
        // RevocationAuditDetails.quoteIfNeeded).
        String safeIssuanceId = RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH);

        return Mono.defer(() -> {
                    log.info("processId={} action={} status=started issuanceId={}", processId, action, safeIssuanceId);
                    return issuanceService.getIssuanceById(issuanceId)
                            .switchIfEmpty(Mono.defer(() -> {
                                safeAuditAttempted(actor, null, issuanceId, reason, processId, action, auditContext);
                                return path.whenMissing().then(Mono.<Issuance>error(new IssuanceNotFoundException(
                                        "No issuance found for issuanceId: " + issuanceId)));
                            }))
                            .doOnSuccess(p -> log.debug(
                                    "processId={} action={} step=issuanceLoaded issuanceId={} credentialStatus={}",
                                    processId, action, safeIssuanceId, p != null ? p.getCredentialStatus() : null
                            ))
                            .doOnNext(issuanceRef::set)
                            .flatMap(issuance -> {
                                safeAuditAttempted(actor, issuance, issuanceId, reason, processId, action, auditContext);
                                return path.validator().validate(processId, tokenValue, issuance)
                                        .doOnSuccess(v -> log.info(
                                                "processId={} action={} step=validationPassed issuanceId={}",
                                                processId, action, safeIssuanceId
                                        ))
                                        .thenReturn(new RevocationContext(tokenValue, issuance));
                            });
                })
                .flatMap(ctx ->
                        statusListProvider.revoke(issuanceId, ctx.token, publicIssuerBaseUrl,
                                        Mono.defer(() -> issuanceService.updateIssuanceStatusToRevoked(ctx.issuance))
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action={} step=issuanceUpdated issuanceId={}",
                                                        processId, action, safeIssuanceId
                                                ))
                                )
                                .onErrorMap(path.markFailure()::apply)
                                // Only once the list and the process have committed together.
                                .then(Mono.defer(() -> issuanceService.extractCredentialId(ctx.issuance)
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
                                ))
                )
                .doOnSuccess(v -> {
                    log.info("processId={} action={} status=completed issuanceId={}",
                            processId, action, safeIssuanceId);
                    // Post-commit: the revocation is already consumed at this point, so a logging
                    // failure inside safeAuditSuccess must never surface as an error here (ES-04).
                    safeAuditSuccess(actor, issuanceRef.get(), issuanceId, reason, processId, action, outcomeContext(path, issuanceRef.get()));
                })
                .doOnError(e -> {
                    // The JDK repeats a malformed id in the message of UUID.fromString.
                    log.warn(
                            "processId={} action={} status=failed issuanceId={} error={}",
                            processId, action, safeIssuanceId,
                            RevocationAuditDetails.quoteIfNeeded(e.toString(), RevocationAuditDetails.MAX_LOG_VALUE_LENGTH)
                    );
                    safeAuditFailure(actor, issuanceRef.get(), issuanceId, reason, processId, action, e, outcomeContext(path, issuanceRef.get()));
                });
    }
}
