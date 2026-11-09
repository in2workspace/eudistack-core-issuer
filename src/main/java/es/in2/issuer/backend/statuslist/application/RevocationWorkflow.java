package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
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
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.statuslist.domain.audit.RevocationAuditEvents;
import es.in2.issuer.backend.statuslist.domain.audit.RevocationAuditEvents.Origin;
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
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
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
    private static final String DETAIL_WORKFLOW_ACTION = "workflowAction";
    private static final String ERROR_TYPE_BAD_REQUEST = "BAD_REQUEST";

    /**
     * Who the token says the requester is, when it carries no W3C attestation: the mandatee, by the email
     * of a person (an SD-JWT attestation) or the DID of a system. {@code sub} comes after them because a
     * system's is the IP address its attestation declares, which does not identify it.
     */
    private static final String MANDATEE_CLAIM = "mandatee";
    private static final List<String> MANDATEE_FIELDS = List.of("email", "id");
    private static final List<String> REQUESTER_CLAIMS = List.of("client_id", "sub", "azp", "jti");

    /** Actor of the system-triggered path fed by the OID4VCI credential_deleted notification. */
    public static final String ACTOR_OID4VCI_NOTIFICATION = "system:oid4vci-notification";

    /** Actor of the system-triggered path fed by the revocation-instruction message queue (EUD-225). */
    public static final String ACTOR_REVOCATION_INSTRUCTION = "system:revocation-instruction";

    private final StatusListProvider statusListProvider;
    private final AccessTokenService accessTokenService;
    private final CallerProvider callerProvider;
    private final PowerAuthorizationService powerAuthorizationService;
    private final IssuanceService issuanceService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final JWTService jwtService;
    private final AuditTrailPort auditTrail;

    private record RevocationContext(String token, Issuance issuance) { }

    /** The caller of the contract's route, as the audit trail names them (AC-10). */
    private record Requester(String actor, String organization) { }

    /**
     * What differs between the entry points of a revocation.
     *
     * @param action       name of the workflow action in logs and audit
     * @param decision     decides whether this caller may revoke this process (nothing for a system trigger)
     * @param statusCheck  decides whether the process, in its current status, can be revoked
     * @param whenMissing  decided before answering that the process does not exist
     * @param markFailure  translates a failure marking the list and committing the process
     * @param auditContext extra fields of every audit event of this entry point
     * @param auditOrigin  what triggered the revocation, for the catalogue's {@code Revocation} event; empty when
     *                     the trigger has no origin there (the revocation-instruction queue)
     */
    private record RevocationPath(String action,
                                  RevocationValidator decision,
                                  Function<Issuance, Mono<Void>> statusCheck,
                                  Mono<Void> whenMissing,
                                  UnaryOperator<Throwable> markFailure,
                                  Map<String, Object> auditContext,
                                  Optional<Origin> auditOrigin) { }

    @FunctionalInterface
    private interface RevocationValidator {
        Mono<Void> validate(String processId, String token, Issuance issuance);
    }

    /**
     * Operator-triggered revocation (portal). A caller token is required, cleaned, propagated to
     * signing, and names the actor of the trace.
     */
    @Observed(name = "revocation.revoke", contextualName = "revocation-revoke")
    public Mono<Void> revoke(String processId, String bearerToken, String issuanceId, String reason, String publicIssuerBaseUrl) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(publicIssuerBaseUrl, "publicIssuerBaseUrl");
        return auditTrail.withCorrelationId(processId, accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> resolveRequesterActor(token)
                        .flatMap(actor -> revokeInternal(
                                        processId,
                                        Optional.of(token),
                                        issuanceId,
                                        reason,
                                        actor,
                                        publicIssuerBaseUrl,
                                        new RevocationPath(
                                                "revokeCredential",
                                                this::authorizeOperatorRevocation,
                                                RevocationWorkflow::requireRevocable,
                                                Mono.defer(() -> authorizeOperatorWithoutResource(token, issuanceId)),
                                                UnaryOperator.identity(),
                                                Map.of(),
                                                Optional.of(Origin.REQUEST)
                                        )
                                ))
                ));
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
        return auditTrail.withCorrelationId(processId, accessTokenService.getCleanBearerToken(bearerToken)
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
                                            (pid, t, issuance) -> decideRevocation(t, issuance),
                                            issuance -> requireRevocable(issuanceId, issuance),
                                            Mono.defer(() -> authorizeOperatorWithoutResource(token, issuanceId)),
                                            error -> toContractFailure(issuanceId, error),
                                            auditContext,
                                            Optional.of(Origin.REQUEST)
                                    )
                            );
                        })));
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
                        (pid, t, issuance) -> Mono.empty(),
                        RevocationWorkflow::requireRevocable,
                        Mono.empty(),
                        UnaryOperator.identity(),
                        tenantSource != null && !tenantSource.isBlank() ? Map.of("tenantSource", tenantSource) : Map.of(),
                        auditOriginOf(actor)
                )
        );
    }

    /**
     * R1 (EUD-253): decided by the caller's powers and the organization stored with the process, the
     * same for a person and a system. The decision goes first so that an attestation outside the
     * caller's scope reads as not found whatever its status, and the platform administrator's attempt
     * on an already revoked one is traced as a security action before it is rejected (AC-10).
     *
     * <p>A process stored without an organization (issued before EUD-272, e.g. Doctor ID) belongs to
     * no organization: it is passed as {@code ""}, never {@code null}, which the decision point reads
     * as "no resource" and would let an organization administrator through.
     */
    private Mono<Void> authorizeOperatorRevocation(String processId, String token, Issuance issuance) {
        log.info("Process ID: {} - Validating 'revoke' action...", processId);
        return decideRevocation(token, issuance);
    }

    private Mono<Void> decideRevocation(String token, Issuance issuance) {
        String organization = Objects.requireNonNullElse(issuance.getOrganizationIdentifier(), "");
        return callerProvider.fromToken(token)
                .flatMap(caller -> powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, caller,
                        organization, String.valueOf(issuance.getIssuanceId())))
                .then();
    }

    private Mono<Void> authorizeOperatorWithoutResource(String token, String issuanceId) {
        return callerProvider.fromToken(token)
                .flatMap(caller -> powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, caller, null, issuanceId))
                .then();
    }

    private static Mono<Void> requireRevocable(Issuance issuance) {
        if (issuance.getCredentialStatus() == CredentialStatusEnum.VALID) {
            return Mono.empty();
        }
        return Mono.error(new InvalidStatusException("Invalid status: " + issuance.getCredentialStatus()));
    }

    /**
     * The actor comes from the access token, which the security chain verified, and never from the
     * principal: the principal is read from an {@code X-ID-Token} whose signature nobody checks, so
     * whoever sends one could name anybody (AC-10). The email of the mandatee of a W3C attestation
     * goes first, then the mandatee of an SD-JWT attestation, by email or by the DID of a system.
     */
    private Mono<Requester> resolveRequester(String bearerToken, String token) {
        Mono<String> organization = accessTokenService.getOrganizationId(bearerToken)
                .onErrorResume(e -> Mono.empty())
                .defaultIfEmpty("");
        return resolveRequesterActor(token).zipWith(organization, Requester::new);
    }

    private Mono<String> resolveRequesterActor(String token) {
        return Mono.fromSupplier(() -> actorFromToken(token).orElseGet(() -> {
            log.warn("Revocation audit: requester not identifiable from the access token");
            return UNKNOWN_ACTOR;
        }));
    }

    /**
     * A request the security chain rejected (AC-10): nothing in it is verified, so the actor is anonymous
     * and the token is not read. The values come from whoever sent it, so they are sanitized here. Never fails.
     *
     * @param declaredClientAddress the address the request says it comes from, not evidence of where it
     *                              came from: behind the proxies it is the first value of {@code Forwarded}
     *                              or {@code X-Forwarded-For}, which the client chooses
     */
    public void traceUnauthenticated(String issuanceId, String reason, String errorType, String declaredClientAddress) {
        try {
            String safeId = RevocationAuditDetails.sanitize(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH);
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    ANONYMOUS_ACTOR, null, safeId, reason, "failure", errorType));
            details.put("processId", UUID.randomUUID().toString());
            details.put(DETAIL_WORKFLOW_ACTION, ACTION_REVOKE_ISSUANCE);
            details.put("declaredClientAddress", RevocationAuditDetails.sanitize(declaredClientAddress, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH));
            auditService.auditFailure(EVENT_FAILED, ANONYMOUS_ACTOR, errorType, details);
        } catch (Exception e) {
            log.warn("Revocation audit: rejected request not traced: {}", e.getClass().getSimpleName());
        }
    }

    private Optional<String> actorFromToken(String token) {
        try {
            Map<String, Object> claims = jwtService.parseJWT(token).getJWTClaimsSet().getClaims();
            Map<?, ?> mandatee = claims.get(MANDATEE_CLAIM) instanceof Map<?, ?> map ? map : Map.of();
            List<Object> candidates = new ArrayList<>();
            candidates.add(jwtService.extractMandateeEmail(claims).orElse(null));
            MANDATEE_FIELDS.forEach(field -> candidates.add(mandatee.get(field)));
            REQUESTER_CLAIMS.forEach(claim -> candidates.add(claims.get(claim)));
            return candidates.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(value -> !value.isBlank())
                    .findFirst();
        } catch (ParseException | RuntimeException e) {
            log.warn("Revocation audit: requester not resolvable from the token: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private void safeAuditAttempted(String actor, Issuance issuance, String issuanceId, String reason,
                                    String processId, String action, Map<String, Object> auditContext) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "attempted", null));
            details.put("processId", processId);
            details.put(DETAIL_WORKFLOW_ACTION, action);
            details.putAll(auditContext);
            auditService.auditAttempted(EVENT_ATTEMPTED, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditAttemptedFailed issuanceId={} error={}",
                    processId, action, RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH), e.toString());
        }
    }

    private void safeAuditSuccess(String actor, Issuance issuance, String issuanceId, String reason,
                                  String processId, String action, Map<String, Object> auditContext) {
        try {
            String orgId = issuance != null ? issuance.getOrganizationIdentifier() : null;
            Map<String, Object> details = new LinkedHashMap<>(RevocationAuditDetails.toDetailsMap(
                    actor, orgId, issuanceId, reason, "success", null));
            details.put("processId", processId);
            details.put(DETAIL_WORKFLOW_ACTION, action);
            details.putAll(auditContext);
            auditService.auditSuccess(EVENT_SUCCESS, actor, "credential", issuanceId, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditSuccessFailed issuanceId={} error={}",
                    processId, action, RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH), e.toString());
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
            details.put(DETAIL_WORKFLOW_ACTION, action);
            details.putAll(auditContext);
            auditService.auditFailure(EVENT_FAILED, actor, errorType, details);
        } catch (Exception e) {
            log.warn("processId={} action={} step=auditFailureFailed issuanceId={} error={}",
                    processId, action, RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH), e.toString());
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
        AtomicBoolean statusListFailed = new AtomicBoolean();
        // issuanceId is boundary-validated as a well-formed UUID on the contract route, the alias
        // (the DTO's @Pattern) and the queue (the mapper's UUID.fromString), but not on PATCH, and
        // this method's log statements are a shared sink for all of them. quoteIfNeeded
        // (for logging only -- the real lookups/audit calls below keep the raw value) both
        // strips control characters and quotes/escapes an embedded '=' or '"', unlike plain
        // sanitize() alone (CodeQL java/log-injection, EUD-225 PR review -- see the note on
        // RevocationAuditDetails.quoteIfNeeded).
        String safeIssuanceId = RevocationAuditDetails.quoteIfNeeded(issuanceId, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH);

        Mono<Void> revocation = Mono.defer(() -> {
                    log.info("processId={} action={} status=started issuanceId={}", processId, action, safeIssuanceId);
                    return issuanceService.getIssuanceById(issuanceId)
                            .switchIfEmpty(Mono.defer(() -> {
                                safeAuditAttempted(actor, null, issuanceId, reason, processId, action, auditContext);
                                // A caller is decided without a resource first, so one who may not revoke is
                                // denied rather than told whether the id exists. A system trigger has no caller.
                                return path.whenMissing().then(Mono.<Issuance>error(new IssuanceNotFoundException("No issuance found for the given id")));
                            }))
                            .doOnSuccess(p -> log.debug(
                                    "processId={} action={} step=issuanceLoaded issuanceId={} credentialStatus={}",
                                    processId, action, safeIssuanceId, p != null ? p.getCredentialStatus() : null
                            ))
                            .doOnNext(issuanceRef::set)
                            .flatMap(issuance -> {
                                safeAuditAttempted(actor, issuance, issuanceId, reason, processId, action, auditContext);
                                return path.decision().validate(processId, tokenValue, issuance)
                                        .then(Mono.defer(() -> path.statusCheck().apply(issuance)))
                                        .doOnSuccess(v -> log.info(
                                                "processId={} action={} step=validationPassed issuanceId={}",
                                                processId, action, safeIssuanceId
                                        ))
                                        .thenReturn(new RevocationContext(tokenValue, issuance));
                            });
                })
                .flatMap(ctx ->
                        statusListProvider.revoke(issuanceId, ctx.token, publicIssuerBaseUrl,
                                        // The Revocation event commits with the list and the process, or none does.
                                        Mono.defer(() -> issuanceService.updateIssuanceStatusToRevoked(ctx.issuance))
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action={} step=issuanceUpdated issuanceId={}",
                                                        processId, action, safeIssuanceId
                                                ))
                                                .then(Mono.defer(() -> stageApplied(
                                                        path.auditOrigin(), issuanceId, reason, ctx.issuance)))
                                )
                                .doOnError(e -> statusListFailed.set(!(e instanceof StatusListIndexNotFoundException)))
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
                    safeAuditSuccess(actor, issuanceRef.get(), issuanceId, reason, processId, action, auditContext);
                })
                .doOnError(e -> {
                    // The JDK repeats a malformed id in the message of UUID.fromString.
                    log.warn(
                            "processId={} action={} status=failed issuanceId={} error={}",
                            processId, action, safeIssuanceId,
                            RevocationAuditDetails.quoteIfNeeded(e.toString(), RevocationAuditDetails.MAX_LOG_VALUE_LENGTH)
                    );
                    safeAuditFailure(actor, issuanceRef.get(), issuanceId, reason, processId, action, e, auditContext);
                });

        return auditTrail.stageOnError(revocation, error ->
                refusalOf(error, path.auditOrigin(), issuanceId, reason, issuanceRef.get(), statusListFailed.get()));
    }

    /** Only a revocation caused by a wallet notification has an origin in the catalogue besides a request. */
    private static Optional<Origin> auditOriginOf(String actor) {
        return ACTOR_OID4VCI_NOTIFICATION.equals(actor) ? Optional.of(Origin.WALLET_NOTIFICATION) : Optional.empty();
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
        if (error instanceof AlreadyRevokedException) {
            return Optional.of("AlreadyRevoked");
        }
        if (error instanceof NotRevocableException) {
            return Optional.of("NotRevocable");
        }
        if (error instanceof InvalidCredentialStatusTransitionException transition) {
            return Optional.of(transition.getFrom() == CredentialStatusEnum.REVOKED ? "AlreadyRevoked" : "NotRevocable");
        }
        if (error instanceof InvalidStatusException) {
            boolean alreadyRevoked = issuance != null && issuance.getCredentialStatus() == CredentialStatusEnum.REVOKED;
            return Optional.of(alreadyRevoked ? "AlreadyRevoked" : "NotRevocable");
        }
        if (error instanceof InsufficientPermissionException || error instanceof UnauthorizedRoleException
                || error instanceof TenantMismatchException) {
            return Optional.of("PolicyDenied");
        }
        if (error instanceof StatusListUnavailableException) {
            return Optional.of("StatusListUnavailable");
        }
        return statusListFailed ? Optional.of("StatusListUnavailable") : Optional.empty();
    }

    /** The holder is only reported once the process was resolved; an unknown process has none to give. */
    private static Holder holderOf(Issuance issuance) {
        return issuance == null ? null : Holder.ofAttestation(issuance.getSubject(), issuance.getEmail(), issuance.getCredentialDataSet());
    }
}
