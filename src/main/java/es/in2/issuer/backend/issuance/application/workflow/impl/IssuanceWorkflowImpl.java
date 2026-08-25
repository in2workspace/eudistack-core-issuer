package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.issuance.domain.model.HolderKey;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuanceWorkflowImpl implements IssuanceWorkflow {

    private static final String DEFAULT_GRANT_TYPE = "authorization_code";
    private static final String DEFAULT_DELIVERY = "email";

    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;
    private final IssuancePdpService issuancePdpService;
    private final PayloadSchemaValidator payloadSchemaValidator;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final IssuanceMetrics issuanceMetrics;
    private final CredentialIssuedLogger credentialIssuedLogger;
    private final AuditService auditService;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final StatusListWorkflow statusListWorkflow;
    private final IssuanceProperties issuanceProperties;

    @Override
    @Observed(name = "issuance.issue-credential", contextualName = "issuance-issue-credential")
    public Mono<IssuanceResponse> issueCredential(
            String processId,
            IssuanceRequest request,
            String idToken,
            String publicIssuerBaseUrl,
            String publicWalletBaseUrl) {

        var sample = issuanceMetrics.startTimer();
        String configId = request.credentialConfigurationId();
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return requireResolvedTenant()
                .then(Mono.defer(() -> validateRequest(request, idToken)))
                .then(Mono.defer(() -> payloadSchemaValidator.validate(configId, request.payload())))
                .then(Mono.defer(() -> issuancePdpService.authorize(configId, request.payload(), idToken)))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, idToken, publicIssuerBaseUrl, publicWalletBaseUrl, delivery)))
                .transformDeferredContextual((flow, ctx) -> {
                    String tenant = ctx.hasKey(TENANT_DOMAIN_CONTEXT_KEY) ? ctx.get(TENANT_DOMAIN_CONTEXT_KEY) : null;
                    return flow
                            .doOnSuccess(r -> {
                                issuanceMetrics.recordSuccess(sample, configId, delivery);
                                // tenant is guaranteed resolved here (requireResolvedTenant already fail-closed
                                // upstream); the blank check is defense-in-depth so a broken context never
                                // fabricates a trace attributed to a default tenant (AC-05/ES-02).
                                if (tenant != null && !tenant.isBlank()) {
                                    auditDeliveryBestEffort(tenant, processId, r != null ? r.deliveryResults() : null);
                                }
                            })
                            .doOnError(e -> {
                                issuanceMetrics.recordError(sample, configId, delivery);
                                log.error(
                                        "ProcessId: {} - Credential issuance failed for credentialConfigurationId={} delivery={}",
                                        processId, configId, delivery, e);
                                if (tenant != null && !tenant.isBlank()) {
                                    auditDeliveryFailureBestEffort(tenant, processId, e);
                                }
                            });
                });
    }

    /** Early guard (AC-05/ES-02): fails closed before anything is validated, built or delivered. */
    private Mono<Void> requireResolvedTenant() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.hasKey(TENANT_DOMAIN_CONTEXT_KEY) ? ctx.get(TENANT_DOMAIN_CONTEXT_KEY) : null;
            if (tenant == null || tenant.isBlank()) {
                return Mono.error(new TenantNotResolvedException(
                        "Cannot process credential issuance without a resolved tenant"));
            }
            return Mono.empty();
        });
    }

    /** Best-effort (ES-03/ES-04): a broken audit channel never reverts an already-completed delivery. */
    private void auditDeliveryBestEffort(String tenant, String processId, List<DeliveryResult> results) {
        try {
            Set<DeliveryResult> resultSet = (results == null || results.isEmpty())
                    ? Set.of(DeliveryResult.failed("unknown", "indeterminate_result"))
                    : Set.copyOf(results);
            auditService.auditDelivery(DeliveryTrace.of(tenant, processId, resultSet));
        } catch (RuntimeException e) {
            log.warn("ProcessId: {} - Failed to build/emit delivery audit trace", processId, e);
        }
    }

    /**
     * Best-effort (ES-03/ES-04), and per-mode whenever the operation actually knew the modes
     * (EUD-170 AC-03).
     *
     * <p>{@link DeliveryFailedException} is the only failure that ran delivery modes, so it is the
     * only one carrying results. Everything else -- validation, tenant resolution, authorization --
     * failed before any mode executed, and for those the indeterminate trace of EUD-170 ES-01 is the
     * honest answer rather than a fabricated per-mode verdict.
     */
    private void auditDeliveryFailureBestEffort(String tenant, String processId, Throwable error) {
        try {
            Set<DeliveryResult> results = (error instanceof DeliveryFailedException failure
                    && !failure.deliveryResults().isEmpty())
                    ? Set.copyOf(failure.deliveryResults())
                    : Set.of(DeliveryResult.failed("unknown", "indeterminate_result"));
            auditService.auditDelivery(DeliveryTrace.of(tenant, processId, results));
        } catch (RuntimeException e) {
            log.warn("ProcessId: {} - Failed to build/emit delivery audit trace", processId, e);
        }
    }

    @Override
    @Observed(name = "issuance.execute-bootstrap", contextualName = "issuance-execute-bootstrap")
    public Mono<IssuanceResponse> issueCredentialWithoutAuthorization(
            String processId,
            IssuanceRequest request,
            String token,
            String publicIssuerBaseUrl,
            String publicWalletBaseUrl) {

        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return validateRequest(request, null)
                .then(Mono.defer(() -> payloadSchemaValidator.validate(request.credentialConfigurationId(), request.payload())))
                // Resolved inside the chain, not before it: keepOnlyOid4vciDeliveryModes throws for a
                // bootstrap request declaring only `direct`, and thrown outside the chain that escaped
                // every @ExceptionHandler and surfaced as a 500 instead of a 400.
                .then(Mono.defer(() -> {
                    final String safeDelivery;
                    try {
                        safeDelivery = keepOnlyOid4vciDeliveryModes(delivery);
                    } catch (IllegalArgumentException ex) {
                        return Mono.error(new InvalidDeliveryModeException(ex.getMessage()));
                    }
                    return performIssuanceFlow(processId, request, token, publicIssuerBaseUrl,
                            publicWalletBaseUrl, safeDelivery);
                }));
    }

    private Mono<Void> validateRequest(IssuanceRequest request, String idToken) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(request.credentialConfigurationId());
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(
                    "Unknown credential_configuration_id: " + request.credentialConfigurationId()));
        }
        if (requiresIdToken(profile) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException(
                    "Missing required ID Token header for VerifiableCertification issuance."));
        }
        return Mono.empty();
    }

    private Mono<IssuanceResponse> performIssuanceFlow(String processId, IssuanceRequest request, String idToken,
                                                        String publicIssuerBaseUrl, String publicWalletBaseUrl, String delivery) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);

        return resolveAndValidateDeliveryModes(configId, profile, delivery)
                .flatMap(modes -> {
                    // Not gated on the direct mode: a type with no cryptographic binding method gets no
                    // wallet proof either, so the request holder_key is the only cnf source there is --
                    // for every delivery mode alike (EUD-33, reversing EUD-168 EC-04).
                    HolderKey holderKey = profile.holderKeyRequired()
                            ? HolderKey.fromJson(request.holderKey()) : null;
                    Map<String, Object> cnf = holderKey != null ? holderKey.cnf() : null;
                    // Persisted so the OID4VCI credential endpoint -- a separate HTTP call, later in
                    // time, with no proof to derive a cnf from -- can recover the binding.
                    String holderCnf = holderKey != null ? holderKey.toJson() : null;
                    return executeIssuanceForModes(processId, request, idToken,
                            publicIssuerBaseUrl, publicWalletBaseUrl, delivery, modes, cnf, holderCnf);
                });
    }

    /**
     * Early guard (ES-01 / AC-05): normalizes the declared delivery modes and validates their eligibility
     * before anything is signed, dispatched or persisted.
     *
     * <p>Eligibility is a property of the credential profile, not a per-tenant setting (EUD-33; this
     * supersedes the withdrawn EUD-169 {@code issuer.delivery.modes.*} configuration). A profile that
     * declares {@code cryptographic_binding_methods_supported} states that the holder key arrives via
     * an OID4VCI proof-of-possession from a wallet -- and direct delivery has neither wallet nor proof,
     * so {@code direct} is impossible for it. {@code email} and {@code ui} are always eligible.
     *
     * <p>Read from the profile rather than from the published issuer metadata on purpose: the credential
     * endpoint used to evaluate the same condition against the metadata object, and the two routes could
     * drift apart. One source of truth, one answer.
     *
     * <p>This decides mode eligibility only, and returns {@link DeliveryModeNotEligibleException} (409)
     * for an ineligible declared mode. The presence and shape of the holder key is a separate,
     * request-level check enforced right after, in {@link #performIssuanceFlow} -- keeping that order
     * means an ineligible mode is reported as such even when a valid holder key was supplied.
     */
    private Mono<Set<DeliveryMode>> resolveAndValidateDeliveryModes(
            String configId, CredentialProfile profile, String delivery) {

        final Set<DeliveryMode> modes;
        try {
            modes = DeliveryMode.parse(delivery);
        } catch (IllegalArgumentException ex) {
            return Mono.error(new InvalidDeliveryModeException(ex.getMessage()));
        }

        for (DeliveryMode mode : modes) {
            if (mode.isDirect() && !profile.directDeliveryEligible()) {
                return Mono.error(new DeliveryModeNotEligibleException(
                        "Delivery mode '" + mode.value + "' is not eligible for credential type: " + configId));
            }
        }
        return Mono.just(modes);
    }

    private Mono<IssuanceResponse> executeIssuanceForModes(String processId, IssuanceRequest request, String idToken,
                                                            String publicIssuerBaseUrl, String publicWalletBaseUrl,
                                                            String delivery, Set<DeliveryMode> modes,
                                                            Map<String, Object> cnf, String holderCnf) {

        boolean hasDirect  = modes.stream().anyMatch(DeliveryMode::isDirect);
        boolean hasOid4vci = modes.stream().anyMatch(m -> m.isOid4vci);
        String oid4vciDelivery = extractOid4vciDelivery(modes);

        Mono<DirectDeliveryOutcome> directOutcome = hasDirect
                ? performDirectIssuance(processId, request, idToken, publicIssuerBaseUrl, delivery, cnf, holderCnf)
                .map(r -> DirectDeliveryOutcome.delivered(r.signedCredential()))
                .doOnSuccess(outcome -> {
                    if (outcome != null) {
                        credentialIssuedLogger.logIssued(request.credentialConfigurationId());
                    }
                })
                .doOnError(e -> {
                    credentialIssuedLogger.logFailed(request.credentialConfigurationId(), e);
                    log.error(
                            "ProcessId: {} - Direct issuance failed for credentialConfigurationId={} delivery={}",
                            processId,
                            request.credentialConfigurationId(),
                            delivery,
                            e
                    );
                })
                // Materialized rather than propagated (EUD-33 AD-4). Propagating made Mono.zip cancel
                // the wallet leg mid-flight, so the caller got a bare 5xx while an offer may already
                // have been cached and an email sent, with nothing in the response or the audit trace
                // saying so. The failure still decides the HTTP status, in resolveResponse.
                .onErrorResume(e -> Mono.just(DirectDeliveryOutcome.failed(e)))
                : Mono.just(DirectDeliveryOutcome.empty());

        Mono<WalletDeliveryOutcome> walletOutcome = hasOid4vci
                ? performOid4VciIssuanceResilient(processId, request, publicIssuerBaseUrl, publicWalletBaseUrl,
                        oid4vciDelivery, holderCnf)
                : Mono.just(WalletDeliveryOutcome.empty());

        return Mono.zip(directOutcome, walletOutcome)
                .flatMap(tuple -> resolveResponse(tuple.getT1(), tuple.getT2(), hasDirect));
    }

    /**
     * Turns both outcomes into either a 200 response or a {@link DeliveryFailedException}
     * (EUD-33 AC-06).
     *
     * <p>The rule: <b>error if {@code direct} was declared and failed, or if no declared mode was
     * delivered; 200 otherwise</b> -- and {@code delivery_results} travels either way.
     *
     * <p>{@code direct} is decisive because the request asked for the credential <em>in the
     * response</em> (FR-03), and a wallet dispatch does not compensate for not returning it: ES-02
     * forbids a 2xx there. Among wallet modes, one delivered <em>is</em> a genuine partial success,
     * because the holder can still obtain the credential through that channel. Before this rule a
     * wallet-only issuance whose only mode failed answered 200, asserting a delivery that never
     * happened.
     */
    private Mono<IssuanceResponse> resolveResponse(DirectDeliveryOutcome direct, WalletDeliveryOutcome wallet,
                                                    boolean directDeclared) {
        List<DeliveryResult> results = new ArrayList<>();
        if (direct.deliveryResult() != null) {
            results.add(direct.deliveryResult());
        }
        results.addAll(wallet.deliveryResults());

        boolean directFailed = directDeclared && direct.failure() != null;
        boolean anyDelivered = results.stream().anyMatch(r ->
                r.status() == DeliveryResult.DeliveryOutcome.DELIVERED
                        || r.status() == DeliveryResult.DeliveryOutcome.DISPATCHED);

        if (directFailed || !anyDelivered) {
            // Fixed message, cause attached but never interpolated: the actionable per-mode detail
            // already travels in delivery_results, and ErrorResponseFactory would surface this text
            // to the client verbatim as `detail`.
            String detail = directFailed
                    ? "Direct delivery failed; the credential was not returned"
                    : "No declared delivery mode completed successfully";
            return Mono.error(new DeliveryFailedException(detail, results, direct.failure()));
        }

        return Mono.just(IssuanceResponse.builder()
                .signedCredential(direct.signedCredential())
                .credentialOfferUri(wallet.credentialOfferUri())
                .deliveryResults(results.isEmpty() ? null : results)
                .build());
    }

    private Mono<WalletDeliveryOutcome> performOid4VciIssuanceResilient(
            String processId, IssuanceRequest request,
            String publicIssuerBaseUrl, String publicWalletBaseUrl, String oid4vciDelivery, String holderCnf) {

        return performOid4VciIssuance(processId, request, publicIssuerBaseUrl, publicWalletBaseUrl,
                        oid4vciDelivery, holderCnf)
                .map(offer -> WalletDeliveryOutcome.of(offer, oid4vciDelivery))
                .timeout(Duration.ofSeconds(issuanceProperties.hybridWalletTimeoutSeconds()))
                .onErrorResume(ex -> {
                    log.warn("ProcessId: {} - Wallet delivery failed (isolated): {}", processId, ex.toString());
                    return Mono.just(WalletDeliveryOutcome.failed(oid4vciDelivery, resolveWalletErrorDetail(ex)));
                });
    }

    private String resolveWalletErrorDetail(Throwable ex) {
        if (ex instanceof TimeoutException) {
            return "Wallet delivery timed out";
        }
        return ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
    }

    /**
     * Internal outcome of the direct path (not exposed in the API).
     *
     * <p>{@code failure} is non-null exactly when the direct leg errored. It is kept rather than
     * propagated so the wallet leg result survives into the response and the audit trace.
     */
    private record DirectDeliveryOutcome(String signedCredential, DeliveryResult deliveryResult, Throwable failure) {
        static DirectDeliveryOutcome empty() {
            return new DirectDeliveryOutcome(null, null, null);
        }

        static DirectDeliveryOutcome delivered(String signedCredential) {
            return new DirectDeliveryOutcome(signedCredential,
                    DeliveryResult.delivered(DeliveryMode.DIRECT.value), null);
        }

        static DirectDeliveryOutcome failed(Throwable error) {
            String detail = error.getMessage() != null ? error.getMessage() : error.getClass().getSimpleName();
            return new DirectDeliveryOutcome(null, DeliveryResult.failed(DeliveryMode.DIRECT.value, detail), error);
        }
    }

    /** Internal outcome of the wallet path — supports multi-mode CSV (email,ui). */
    private record WalletDeliveryOutcome(String credentialOfferUri, List<DeliveryResult> deliveryResults) {
        static WalletDeliveryOutcome empty() {
            return new WalletDeliveryOutcome(null, List.of());
        }

        /**
         * Per-channel outcome of a dispatch that ran (EUD-33 EC-05): a channel is failed only when
         * its own transport failed, so an SMTP outage no longer condemns the QR channel that shared
         * the dispatch, nor discards the offer identifier that QR needs.
         */
        static WalletDeliveryOutcome of(CredentialOfferResult offer, String oid4vciDelivery) {
            List<DeliveryResult> results = declaredModes(oid4vciDelivery).stream()
                    .map(mode -> offer.failedModes().containsKey(mode)
                            ? DeliveryResult.failed(mode.value, offer.failedModes().get(mode))
                            : DeliveryResult.dispatched(mode.value))
                    .toList();
            return new WalletDeliveryOutcome(offer.credentialOfferUri(), results);
        }

        /** The dispatch never ran (dependency down, timeout): every declared channel is failed. */
        static WalletDeliveryOutcome failed(String oid4vciDelivery, String error) {
            List<DeliveryResult> results = declaredModes(oid4vciDelivery).stream()
                    .map(mode -> DeliveryResult.failed(mode.value, error))
                    .toList();
            return new WalletDeliveryOutcome(null, results);
        }

        private static List<DeliveryMode> declaredModes(String oid4vciDelivery) {
            // EnumSet, not the parsed Set: DeliveryMode.parse collects into a HashSet, whose enum
            // iteration order is identity-hash based and therefore varies between JVM runs, which
            // would make the order of delivery_results unstable.
            return EnumSet.copyOf(DeliveryMode.parse(oid4vciDelivery)).stream().toList();
        }
    }

    /**
     * @param token the {@code X-Id-Token} header, propagated only because the status list and signing
     *              signatures still carry a caller-token parameter. Nothing downstream reads it
     *              (AD-1/EUD-225: vestigial -- it never authorizes and never signs), and it is
     *              {@code null} for every profile that does not declare {@code RequireCertificationIssuance},
     *              which is legal. Do not reintroduce a non-null guard on it: that is exactly what turned
     *              a direct issuance without the header into a 500.
     */
    private Mono<IssuanceResponse> performDirectIssuance(String processId, IssuanceRequest request, String token,
                                                          String publicIssuerBaseUrl, String originalDelivery,
                                                          Map<String, Object> cnf, String holderCnf) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String credentialFormat = profile.format() != null ? profile.format() : JWT_VC_JSON;
        StatusListFormat statusFormat = DC_SD_JWT.equals(credentialFormat)
                ? StatusListFormat.TOKEN_JWT : StatusListFormat.BITSTRING_VC;

        UUID issuanceId = UUID.randomUUID();

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult ->
                        genericCredentialBuilder.bindIssuer(profile, buildResult.credentialDataSet(),
                                        issuanceId.toString(), request.email())
                                .flatMap(enrichedDataSet ->
                                        statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, statusFormat,
                                                        issuanceId.toString(), token, publicIssuerBaseUrl)
                                                .map(entry -> {
                                                    CredentialStatus credStatus = CredentialStatus.fromStatusListEntry(entry);
                                                    return genericCredentialBuilder.injectCredentialStatus(
                                                            enrichedDataSet, credStatus, credentialFormat);
                                                })
                                )
                                .flatMap(enrichedWithStatus ->
                                        credentialSignerWorkflow.signCredential(
                                                        token, enrichedWithStatus, configId, credentialFormat,
                                                        cnf, issuanceId.toString(), request.email())
                                                .flatMap(signedCredential -> {
                                                    CredentialStatusEnum finalStatus = determineFinalStatus(buildResult);
                                                    Issuance issuance = buildDirectIssuanceEntity(
                                                            issuanceId, configId, credentialFormat,
                                                            buildResult, enrichedWithStatus,
                                                            request.email(), originalDelivery, finalStatus,
                                                            holderCnf);
                                                    return issuanceService.saveIssuance(issuance)
                                                            .doOnSuccess(saved -> log.debug(
                                                                    "ProcessId: {} - Direct issuance saved: {} status={}",
                                                                    processId, saved.getIssuanceId(), finalStatus))
                                                            .thenReturn(IssuanceResponse.builder()
                                                                    .signedCredential(signedCredential)
                                                                    .build());
                                                })
                                )
                );
    }

    private Mono<CredentialOfferResult> performOid4VciIssuance(String processId, IssuanceRequest request,
                                                           String publicIssuerBaseUrl, String publicWalletBaseUrl,
                                                           String oid4vciDelivery, String holderCnf) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String grantType = request.grantType() != null ? request.grantType() : DEFAULT_GRANT_TYPE;

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult -> {
                    UUID issuanceId = UUID.randomUUID();
                    Issuance issuance = buildIssuanceEntity(issuanceId, configId, profile.format(),
                            buildResult, request.email(), oid4vciDelivery, holderCnf);

                    return issuanceService.saveIssuance(issuance)
                            .doOnSuccess(saved -> log.debug("ProcessId: {} - Created OID4VCI issuance: {}", processId, saved.getIssuanceId()))
                            .flatMap(saved -> credentialOfferService.createAndDeliverCredentialOffer(
                                    saved.getIssuanceId().toString(), configId, grantType, request.email(),
                                    oid4vciDelivery, saved.getCredentialOfferRefreshToken(),
                                    publicIssuerBaseUrl, publicWalletBaseUrl));
                });
    }

    private Issuance buildIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                          CredentialBuildResult buildResult, String email, String delivery,
                                          String holderCnf) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDataSet(buildResult.credentialDataSet())
                .credentialFormat(credentialFormat)
                .organizationIdentifier(buildResult.organizationIdentifier())
                .credentialType(credentialType)
                .subject(buildResult.subject())
                .validFrom(buildResult.validFrom())
                .validUntil(buildResult.validUntil())
                .email(email)
                .delivery(delivery)
                .holderCnf(holderCnf)
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .build();
    }

    private Issuance buildDirectIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                                CredentialBuildResult buildResult, String enrichedDataSet,
                                                String email, String delivery, CredentialStatusEnum status,
                                                String holderCnf) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(status)
                .credentialDataSet(enrichedDataSet)
                .credentialFormat(credentialFormat)
                .organizationIdentifier(buildResult.organizationIdentifier())
                .credentialType(credentialType)
                .subject(buildResult.subject())
                .validFrom(buildResult.validFrom())
                .validUntil(buildResult.validUntil())
                .email(email)
                .delivery(delivery)
                .holderCnf(holderCnf)
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .build();
    }

    private CredentialStatusEnum determineFinalStatus(CredentialBuildResult buildResult) {
        if (buildResult.validFrom() != null
                && buildResult.validFrom().toInstant().isAfter(Instant.now())) {
            return CredentialStatusEnum.ISSUED;
        }
        return CredentialStatusEnum.VALID;
    }

    /**
     * The OID4VCI modes of the request as a CSV, in stable enum order.
     *
     * <p>Ordered on purpose: {@code DeliveryMode.parse} collects into a {@code HashSet}, whose enum
     * iteration order is identity-hash based and varies between JVM runs. This CSV reaches both
     * {@code delivery_results} and the persisted {@code delivery} column, so an unstable order would
     * make both non-deterministic.
     */
    private String extractOid4vciDelivery(Set<DeliveryMode> modes) {
        return Arrays.stream(DeliveryMode.values())
                .filter(modes::contains)
                .filter(m -> m.isOid4vci)
                .map(m -> m.value)
                .collect(Collectors.joining(","));
    }

    private String keepOnlyOid4vciDeliveryModes(String delivery) {
        String oid4vciDelivery = DeliveryMode.parse(delivery).stream()
                .filter(m -> m.isOid4vci)
                .map(m -> m.value)
                .collect(Collectors.joining(","));

        if (oid4vciDelivery.isBlank()) {
            throw new IllegalArgumentException(
                    "Bootstrap issuance requires at least one OID4VCI delivery mode."
            );
        }

        return oid4vciDelivery;
    }

    private boolean requiresIdToken(CredentialProfile profile) {
        return profile.issuancePolicy() != null
                && profile.issuancePolicy().rules() != null
                && profile.issuancePolicy().rules().contains("RequireCertificationIssuance");
    }
}
