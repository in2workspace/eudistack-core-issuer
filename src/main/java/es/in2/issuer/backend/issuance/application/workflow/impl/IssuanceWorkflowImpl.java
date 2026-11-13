package es.in2.issuer.backend.issuance.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.oidc4vci.application.workflow.impl.Oid4VciCredentialWorkflowImpl;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.HolderCnfJson;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.issuance.domain.model.HolderKey;
import es.in2.issuer.backend.issuance.domain.model.OfferGrantType;
import es.in2.issuer.backend.issuance.domain.model.RequestedValidity;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.ValidityWindow;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.HolderBindingExemption;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.signing.domain.util.SigningConfigScope;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuanceWorkflowImpl implements IssuanceWorkflow {

    private static final String DEFAULT_DELIVERY = "email";
    /** Detail of {@code invalid_delivery_mode}: never echoes the value sent, which may be any string. */
    static final String INVALID_DELIVERY_MESSAGE = "delivery must be one of: email, ui, direct";
    private static final String INVALID_DELIVERY_LABEL = "invalid";

    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;
    private final PowerAuthorizationService powerAuthorizationService;
    private final IssuancePayloadNormalizer issuancePayloadNormalizer;
    private final PayloadSchemaValidator payloadSchemaValidator;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final IssuanceMetrics issuanceMetrics;
    private final CredentialIssuedLogger credentialIssuedLogger;
    private final AuditService auditService;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final StatusListWorkflow statusListWorkflow;
    private final DeliveryEligibilityResolver deliveryEligibilityResolver;
    private final IssuanceProperties issuanceProperties;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;
    private final HolderDidFallbackAuditor holderDidFallbackAuditor;
    private final TenantCredentialProfileService tenantCredentialProfileService;

    @Override
    @Observed(name = "issuance.issue-credential", contextualName = "issuance-issue-credential")
    public Mono<IssuanceResponse> issueCredential(
            String processId,
            IssuanceRequest request,
            String bearerToken,
            String publicIssuerBaseUrl) {

        var sample = issuanceMetrics.startTimer();
        String configId = request.credentialConfigurationId();
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;
        // Metrics and logs never carry the value the client sent: it is only checked later (EUD-254 §3).
        String deliveryLabel = DeliveryMode.fromValue(delivery).map(mode -> mode.value).orElse(INVALID_DELIVERY_LABEL);

        return requireResolvedTenant()
                .then(Mono.defer(() -> validateRequest(request)))
                .then(Mono.defer(() -> requireTypeEnabled(configId)))
                .then(Mono.fromSupplier(() -> prepared(request)))
                .flatMap(prepared -> payloadSchemaValidator.validate(configId, prepared.request().payload())
                        .then(Mono.defer(() -> powerAuthorizationService.authorizeIssuance(processId, configId,
                                credentialProfileRegistry.getByConfigurationId(configId).credentialType(),
                                prepared.request().organization(), prepared.request().payload())))
                        // FR-07: the process belongs to the organization the decision set, never to the content.
                        .flatMap(authorization -> performIssuanceFlow(processId,
                                prepared.request().withOrganization(authorization.organizationIdentifier()),
                                bearerToken, publicIssuerBaseUrl, delivery, prepared.validity())))
                .transformDeferredContextual((flow, ctx) -> {
                    String tenant = ctx.hasKey(TENANT_DOMAIN_CONTEXT_KEY) ? ctx.get(TENANT_DOMAIN_CONTEXT_KEY) : null;
                    return flow
                            .doOnSuccess(r -> {
                                issuanceMetrics.recordSuccess(sample, configId, deliveryLabel);
                                // tenant is guaranteed resolved here (requireResolvedTenant already fail-closed
                                // upstream); the blank check is defense-in-depth so a broken context never
                                // fabricates a trace attributed to a default tenant (AC-05/ES-02).
                                if (tenant != null && !tenant.isBlank()) {
                                    auditDeliveryBestEffort(tenant, processId, r != null ? r.deliveryResults() : null);
                                }
                            })
                            .doOnError(e -> {
                                issuanceMetrics.recordError(sample, configId, deliveryLabel);
                                log.error(
                                        "ProcessId: {} - Credential issuance failed for credentialConfigurationId={} delivery={}",
                                        processId, configId, deliveryLabel, e);
                                if (tenant != null && !tenant.isBlank()) {
                                    auditDeliveryFailureBestEffort(tenant, processId);
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
     * FR-13: the issued attestation, its organization and type, under the same {@code processId} as the
     * authorization decision that names the caller's attestation -- together they are the evidence of
     * who asked for what. Best-effort: the process is already saved.
     */
    private void auditIssuanceCreatedBestEffort(String processId, Issuance issuance) {
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("processId", processId);
            details.put("organization", issuance.getOrganizationIdentifier());
            details.put("credentialType", issuance.getCredentialType());
            auditService.auditSuccess("issuance.created", issuance.getOrganizationIdentifier(), "issuance",
                    String.valueOf(issuance.getIssuanceId()), details);
        } catch (RuntimeException e) {
            log.warn("ProcessId: {} - Failed to emit issuance audit trace", processId, e);
        }
    }

    /** Best-effort (ES-03/ES-04). Failure path has no per-mode result (ES-01: indeterminate). */
    private void auditDeliveryFailureBestEffort(String tenant, String processId) {
        try {
            auditService.auditDelivery(DeliveryTrace.of(tenant, processId,
                    Set.of(DeliveryResult.failed("unknown", "indeterminate_result"))));
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
            String publicIssuerBaseUrl) {

        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return Mono.fromCallable(() -> keepOnlyOid4vciDeliveryModes(delivery))
                .flatMap(safeDelivery -> validateRequest(request)
                        .then(Mono.fromSupplier(() -> prepared(request)))
                        .flatMap(prepared -> payloadSchemaValidator.validate(prepared.request().credentialConfigurationId(), prepared.request().payload())
                                .then(Mono.defer(() -> performIssuanceFlow(processId, prepared.request(), token,
                                        publicIssuerBaseUrl, safeDelivery, prepared.validity())))));
    }

    /** A request whose payload is normalized and split from the validity dates it asks for (EUD-254 §5). */
    private record PreparedRequest(IssuanceRequest request, RequestedValidity validity) {
    }

    /** What building the credential takes besides the request: the tenant's catalog entry and the accepted window. */
    private record CredentialTerms(CatalogEntry entry, ValidityWindow window) {
    }

    private PreparedRequest prepared(IssuanceRequest request) {
        JsonNode normalizedPayload = Objects.requireNonNull(
                issuancePayloadNormalizer.normalize(request.credentialConfigurationId(), request.payload()),
                "The issuance payload normalizer must not return null");
        RequestedValidity.Split split = RequestedValidity.split(normalizedPayload);
        return new PreparedRequest(request.withPayload(split.payload()), split.validity());
    }

    private Mono<Void> validateRequest(IssuanceRequest request) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(request.credentialConfigurationId());
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(
                    "Unknown credential_configuration_id: " + request.credentialConfigurationId()));
        }
        return Mono.empty();
    }

    /**
     * EUD-254 FR-07 and §3: a type the tenant has not enabled is unsupported, like an unknown one, and is
     * rejected before the schema and the permission. It is the catalog that decides which types a tenant
     * issues, not the caller's powers (EUD-253 1.0.0 retired its AC-15). Bootstrap issuance keeps its own
     * check, the 409 of the eligible delivery modes.
     */
    private Mono<Void> requireTypeEnabled(String configId) {
        return tenantCredentialProfileService.isProfileAllowed(configId)
                .flatMap(enabled -> Boolean.TRUE.equals(enabled)
                        ? Mono.<Void>empty()
                        : Mono.error(new CredentialTypeUnsupportedException(
                                "credential_configuration_id is not enabled in the tenant: " + configId)));
    }

    /**
     * @param bearerToken the caller's token, used by the direct mode alone: it signs the credential and
     *                    may have to sign a new status list inside this same request (EUD-168).
     */
    private Mono<IssuanceResponse> performIssuanceFlow(String processId, IssuanceRequest request, String bearerToken,
                                                        String publicIssuerBaseUrl, String delivery,
                                                        RequestedValidity requestedValidity) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);

        // EUD-254 §3: delivery mode, grant, validity and holder key, in this order, before anything is created.
        return resolveAndValidateDeliveryMode(configId, delivery)
                // Whatever the mode: the direct mode builds no offer and ignores a valid grant.
                .doOnNext(mode -> OfferGrantType.fromRequest(request.grantType()))
                .flatMap(mode -> credentialTerms(configId, requestedValidity)
                        .flatMap(terms -> executeIssuance(processId, request, bearerToken,
                                publicIssuerBaseUrl, mode, holderCnf(configId, profile, request), terms)));
    }

    /** The tenant's catalog entry, and the validity window requested and accepted against it (EUD-254 FR-06). */
    private Mono<CredentialTerms> credentialTerms(String configId, RequestedValidity requestedValidity) {
        return catalogEntry(configId).map(entry -> new CredentialTerms(entry.orElse(null),
                requestedValidity.resolve(entry.orElse(null), Instant.now())));
    }

    /**
     * Scoped exception (AD-8): the machine LEARCredential types keep a cnf even though their schema
     * declares no binding, sourced from the request holder_key. Not gated on the direct mode -- with
     * proof_types_supported gone no key proof arrives through the wallet flow either, so the request is
     * the only source of a holder key there is.
     *
     * <p>Gated on !profile.requiresHolderBinding() as well as the id prefix (F4/S4): the prefix match alone
     * would also fire for a future profile of the same family that recovers proof_types_supported, which
     * would make holder_key required again for a type the schema now binds through a real key proof --
     * exactly the invariant AD-9 exists to protect. HolderKey.fromJson requires the jwk member
     * (code-review F1a/D3): kid/x5c carry no key material this path -- no wallet, no OID4VCI proof -- could
     * ever verify.
     */
    private static Map<String, Object> holderCnf(String configId, CredentialProfile profile, IssuanceRequest request) {
        return HolderBindingExemption.isExempt(configId) && !profile.requiresHolderBinding()
                ? HolderKey.fromJson(request.holderKey()).cnf() : null;
    }

    /**
     * Early guard: checks the requested delivery mode and its eligibility before anything is signed,
     * dispatched or persisted.
     *
     * <p>Eligibility resolves as {@code tenant configuration ∩ schema ceiling}, with the ceiling as the
     * default when no configuration exists. The ceiling ({@link SchemaDeliveryCeiling}) derives from
     * {@code proof_types_supported}, the single signal of holder binding (ADR-110): direct delivery has
     * no wallet and therefore no proof-of-possession, so a bound type cannot be delivered that way.
     *
     * <p>The intersection is what makes this a ceiling rather than a default. Tenant configuration can
     * only narrow it -- a stored configuration listing {@code direct} for a bound type, written before
     * this rule existed, is intersected away instead of honoured.
     *
     * <p>This decides mode eligibility only. Whether a holder key is present and well-formed is a
     * separate, request-level check made right after in {@link #performIssuanceFlow}; keeping that order
     * means an ineligible mode is reported as such even when a valid holder key was supplied.
     */
    private Mono<DeliveryMode> resolveAndValidateDeliveryMode(String configId, String delivery) {

        final DeliveryMode mode;
        try {
            mode = requestedMode(delivery);
        } catch (InvalidDeliveryModeException ex) {
            return Mono.error(ex);
        }

        // Fast-path, no longer strictly necessary (the resolver below applies the same ceiling
        // intersection): keeps a configuration predating the ceiling from silently resurrecting
        // direct delivery for a bound type without waiting on the resolver's round trip.
        try {
            schemaDeliveryCeiling.validateWithinCeiling(configId, Set.of(mode));
        } catch (DeliveryModeNotEligibleException ex) {
            return Mono.error(ex);
        }

        return deliveryEligibilityResolver.resolveEligibleModes(configId)
                .flatMap(eligible -> eligible.contains(mode)
                        ? Mono.just(mode)
                        : Mono.error(notEligible(configId, mode, eligible)));
    }

    private static DeliveryModeNotEligibleException notEligible(String configId, DeliveryMode mode,
                                                                Set<DeliveryMode> eligible) {
        String eligibleModes = eligible.isEmpty() ? "none" : DeliveryMode.toCanonicalCsv(eligible);
        return new DeliveryModeNotEligibleException("Delivery mode '" + mode.value
                + "' is not eligible for credential type '" + configId + "'. Eligible modes: " + eligibleModes);
    }

    /**
     * EUD-254: one delivery mode, one flow. Nothing is delivered when it fails, so the failure is not a
     * per-mode result: it propagates and is answered as a problem.
     */
    private Mono<IssuanceResponse> executeIssuance(String processId, IssuanceRequest request, String bearerToken,
                                                   String publicIssuerBaseUrl, DeliveryMode mode,
                                                   Map<String, Object> cnf, CredentialTerms terms) {
        return mode.isDirect()
                ? executeDirectDelivery(processId, request, bearerToken, publicIssuerBaseUrl, cnf, terms)
                : executeWalletDelivery(processId, request, publicIssuerBaseUrl, mode, cnf, terms);
    }

    private Mono<IssuanceResponse> executeDirectDelivery(String processId, IssuanceRequest request, String bearerToken,
                                                         String publicIssuerBaseUrl, Map<String, Object> cnf,
                                                         CredentialTerms terms) {
        String configId = request.credentialConfigurationId();
        return performDirectIssuance(processId, request, bearerToken, publicIssuerBaseUrl, cnf, terms)
                .doOnNext(issued -> credentialIssuedLogger.logIssued(configId))
                .map(issued -> IssuanceResponse.builder()
                        .signedCredential(issued.signedCredential())
                        .deliveryResults(List.of(DeliveryResult.delivered(DeliveryMode.DIRECT.value)))
                        .issuanceId(issued.issuanceId())
                        .build())
                .doOnError(e -> credentialIssuedLogger.logFailed(configId, e));
    }

    /**
     * The credential offer, by email or returned to the interface. A bounced email is a failed delivery:
     * with one mode there is nothing else to return.
     */
    private Mono<IssuanceResponse> executeWalletDelivery(String processId, IssuanceRequest request,
                                                         String publicIssuerBaseUrl, DeliveryMode mode,
                                                         Map<String, Object> cnf, CredentialTerms terms) {
        return performOid4VciIssuance(processId, request, publicIssuerBaseUrl, mode.value, cnf, terms)
                .timeout(Duration.ofSeconds(issuanceProperties.hybridWalletTimeoutSeconds()))
                .onErrorMap(TimeoutException.class,
                        e -> new DeliveryFailedException(DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT, e))
                .flatMap(offer -> offer.emailError() != null
                        ? Mono.error(new DeliveryFailedException(DeliveryErrorCode.DELIVERY_FAILED,
                                new EmailCommunicationException(offer.emailError())))
                        : Mono.just(IssuanceResponse.builder()
                                .credentialOfferUri(offer.credentialOfferUri())
                                .deliveryResults(List.of(DeliveryResult.dispatched(mode.value)))
                                .issuanceId(offer.issuanceId())
                                .build()));
    }

    /**
     * What the wallet flow produced: the offer URI, the email failure the offer service reported
     * rather than threw, and the stored process.
     */
    private record Oid4VciLegResult(String credentialOfferUri, String emailError, String issuanceId) {}

    /**
     * {@code cnf} is only ever non-null here for an AD-8 exempt type (F4), and only ever jwk-shaped for
     * one (kid/x5c never reach this leg -- see {@link es.in2.issuer.backend.issuance.domain.model.HolderKey}).
     * Deriving the did:key from it (delegated to {@link HolderDidFallbackAuditor}, shared with
     * {@link Oid4VciCredentialWorkflowImpl}'s wallet leg) is what lets the direct leg enforce the same
     * cnf-mandatee.id invariant the wallet leg already does from a key proof (F2).
     */
    private Mono<IssuanceResponse> performDirectIssuance(String processId, IssuanceRequest request, String token,
                                                          String publicIssuerBaseUrl,
                                                          Map<String, Object> cnf, CredentialTerms terms) {
        UUID issuanceId = UUID.randomUUID();

        // bindIssuer and the signature use the same signing configuration. If it changes in
        // between, the scope runs issueDirectly again with the same issuanceId: a failure before the save
        // releases the status list entry, and the credential built the first time never left the Issuer.
        return SigningConfigScope.run(() ->
                issueDirectly(processId, request, token, publicIssuerBaseUrl, cnf, terms, issuanceId));
    }

    private Mono<IssuanceResponse> issueDirectly(String processId, IssuanceRequest request, String token,
                                                 String publicIssuerBaseUrl,
                                                 Map<String, Object> cnf, CredentialTerms terms, UUID issuanceId) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String credentialFormat = profile.format() != null ? profile.format() : JWT_VC_JSON;
        StatusListFormat statusFormat = DC_SD_JWT.equals(credentialFormat)
                ? StatusListFormat.TOKEN_JWT : StatusListFormat.BITSTRING_VC;

        return buildCredential(profile, request, terms)
                .flatMap(buildResult ->
                        genericCredentialBuilder.bindIssuer(profile, buildResult.credentialDataSet(),
                                        issuanceId.toString(), request.email())
                                .map(enrichedDataSet -> {
                                    // AD-8 exempt types take no key proof (F2, S2): derive the holder DID
                                    // from the cnf.jwk the exemption already resolved, so cnf and
                                    // mandatee.id agree on the same key pair -- the same invariant the
                                    // wallet leg enforces via Oid4VciCredentialWorkflowImpl.
                                    String holderDid = holderDidFallbackAuditor.deriveFromJwkCnf(
                                            processId, issuanceId.toString(), cnf);
                                    return holderDid != null
                                            ? genericCredentialBuilder.bindHolderDid(enrichedDataSet, holderDid)
                                            : enrichedDataSet;
                                })
                                .flatMap(enrichedDataSet ->
                                        statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, statusFormat,
                                                        issuanceId.toString(), token, publicIssuerBaseUrl)
                                                .onErrorMap(failedAt(DeliveryErrorCode.STATUS_LIST_UNAVAILABLE))
                                                .flatMap(entry -> {
                                                    CredentialStatus credStatus = CredentialStatus.fromStatusListEntry(entry);
                                                    String enrichedWithStatus = genericCredentialBuilder.injectCredentialStatus(
                                                            enrichedDataSet, credStatus, credentialFormat);
                                                    return credentialSignerWorkflow.signCredential(
                                                                    token, enrichedWithStatus, configId, credentialFormat,
                                                                    cnf, issuanceId.toString(), request.email())
                                                            .onErrorMap(failedAt(DeliveryErrorCode.SIGNING_FAILED))
                                                            .flatMap(signedCredential -> {
                                                                CredentialStatusEnum finalStatus = determineFinalStatus(buildResult);
                                                                Issuance issuance = buildDirectIssuanceEntity(
                                                                        issuanceId, configId, credentialFormat,
                                                                        buildResult, enrichedWithStatus, organizationOf(request),
                                                                        request.email(), DeliveryMode.DIRECT.value, finalStatus, cnf);
                                                                return issuanceService.saveIssuance(issuance)
                                                                        .doOnSuccess(saved -> auditIssuanceCreatedBestEffort(processId, issuance))
                                                                        .doOnSuccess(saved -> log.debug(
                                                                                "ProcessId: {} - Direct issuance saved: {} status={}",
                                                                                processId, saved.getIssuanceId(), finalStatus))
                                                                        .onErrorMap(failedAt(DeliveryErrorCode.PERSISTENCE_FAILED))
                                                                        .thenReturn(IssuanceResponse.builder()
                                                                                .signedCredential(signedCredential)
                                                                                .issuanceId(issuanceId.toString())
                                                                                .build());
                                                            });
                                                })
                                                // W1 (code-review): covers allocate + inject + sign + save under one
                                                // release. injectCredentialStatus used to run in a separate .map()
                                                // stage outside this resume's scope, so a malformed enrichedDataSet
                                                // threw past it and leaked the entry allocateEntry had just reserved.
                                                // releaseStatusListEntryBestEffort's delete is a no-op when nothing
                                                // was ever allocated, so covering the allocate failure too is harmless.
                                                .onErrorResume(error -> releaseStatusListEntryBestEffort(processId, issuanceId, error))
                                )
                );
    }

    /**
     * Tags the stage of the delivery that failed with its closed code (EUD-254 AC-03), unless an inner
     * stage already did. The original exception is kept as the cause: it is what gets logged, and the
     * signing configuration scope still finds a configuration change through it.
     */
    private static Function<Throwable, Throwable> failedAt(DeliveryErrorCode code) {
        return ex -> ex instanceof DeliveryFailedException ? ex : new DeliveryFailedException(code, ex);
    }

    private Mono<Oid4VciLegResult> performOid4VciIssuance(String processId, IssuanceRequest request,
                                                           String publicIssuerBaseUrl, String oid4vciDelivery,
                                                           Map<String, Object> cnf, CredentialTerms terms) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String grantType = OfferGrantType.fromRequest(request.grantType()).value();

        return buildCredential(profile, request, terms)
                .flatMap(buildResult -> {
                    UUID issuanceId = UUID.randomUUID();
                    // The cnf travels on the row, not in this request: the wallet legs sign in a
                    // later request to the Credential Endpoint, where the holder key of an exempt
                    // type has no other source (AD-8).
                    Issuance issuance = buildIssuanceEntity(
                            issuanceId,
                            request,
                            profile,
                            buildResult,
                            oid4vciDelivery,
                            cnf,
                            grantType);

                    return issuanceService.saveIssuance(issuance)
                            .onErrorMap(failedAt(DeliveryErrorCode.PERSISTENCE_FAILED))
                            .doOnSuccess(saved -> log.debug("ProcessId: {} - Created OID4VCI issuance: {}", processId, saved.getIssuanceId()))
                            .doOnSuccess(saved -> auditIssuanceCreatedBestEffort(processId, issuance))
                            .flatMap(saved -> credentialOfferService.createAndDeliverCredentialOffer(
                                            saved.getIssuanceId().toString(), configId, grantType, request.email(),
                                            oid4vciDelivery, saved.getCredentialOfferRefreshToken(),
                                            publicIssuerBaseUrl)
                                    .onErrorMap(failedAt(DeliveryErrorCode.DELIVERY_FAILED))
                                    .map(offerResult -> new Oid4VciLegResult(
                                            offerResult.credentialOfferUri(), offerResult.emailError(),
                                            saved.getIssuanceId().toString()))
                            );
                });
    }

    /**
     * The tenant's catalog entry of the type. A row not filled yet falls back to the type file (D9); an
     * entry that is not enabled would have been rejected by the PDP already, so there is nothing else to
     * fall back from.
     */
    private Mono<Optional<CatalogEntry>> catalogEntry(String configId) {
        return tenantCredentialProfileService.findEnabledEntry(configId)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty());
    }

    /** Builds the credential with the subject of the catalog entry and the validity the issuance accepted. */
    private Mono<CredentialBuildResult> buildCredential(CredentialProfile profile, IssuanceRequest request,
                                                        CredentialTerms terms) {
        return genericCredentialBuilder.buildCredential(profile, request.payload(), terms.entry(), terms.window());
    }

    private Issuance buildIssuanceEntity(
            UUID issuanceId,
            IssuanceRequest request,
            CredentialProfile profile,
            CredentialBuildResult buildResult,
            String delivery,
            Map<String, Object> cnf,
            String grantType) {

        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDataSet(buildResult.credentialDataSet())
                .credentialFormat(profile.format())
                .organizationIdentifier(organizationOf(request))
                .credentialType(request.credentialConfigurationId())
                .subject(buildResult.subject())
                .validFrom(buildResult.validFrom())
                .validUntil(buildResult.validUntil())
                .email(request.email())
                .delivery(delivery)
                .grantType(grantType)
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .holderCnf(HolderCnfJson.write(cnf))
                .build();
    }

    private <T> Mono<T> releaseStatusListEntryBestEffort(String processId, UUID issuanceId, Throwable original) {
        return statusListWorkflow.releaseEntry(issuanceId.toString())
                .doOnSuccess(v -> log.debug(
                        "ProcessId: {} - Released orphaned status list entry for issuanceId={} after {}",
                        processId, issuanceId, original.getClass().getSimpleName()))
                .onErrorResume(releaseError -> {
                    log.warn("ProcessId: {} - Failed to release status list entry for issuanceId={} (leaked): {}",
                            processId, issuanceId, releaseError.toString());
                    return Mono.empty();
                })
                .then(Mono.<T>error(original));
    }

    private Issuance buildDirectIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                                CredentialBuildResult buildResult, String enrichedDataSet,
                                                String organizationIdentifier,
                                                String email, String delivery, CredentialStatusEnum status,
                                                Map<String, Object> cnf) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(status)
                .credentialDataSet(enrichedDataSet)
                .credentialFormat(credentialFormat)
                .organizationIdentifier(organizationIdentifier)
                .credentialType(credentialType)
                .subject(buildResult.subject())
                .validFrom(buildResult.validFrom())
                .validUntil(buildResult.validUntil())
                .email(email)
                .delivery(delivery)
                .grantType(AUTHORIZATION_CODE)
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .holderCnf(HolderCnfJson.write(cnf))
                .build();
    }

    private CredentialStatusEnum determineFinalStatus(CredentialBuildResult buildResult) {
        if (buildResult.validFrom() != null
                && buildResult.validFrom().toInstant().isAfter(Instant.now())) {
            return CredentialStatusEnum.ISSUED;
        }
        return CredentialStatusEnum.VALID;
    }

    private String keepOnlyOid4vciDeliveryModes(String delivery) {
        DeliveryMode mode = requestedMode(delivery);
        if (!mode.isOid4vci) {
            throw new InvalidDeliveryModeException("Bootstrap issuance requires the email or ui delivery mode");
        }
        return mode.value;
    }

    /**
     * EUD-254: one delivery mode per request, exactly one of its three values. A list of modes, an
     * unknown value, an empty one or one with spaces is {@code invalid_delivery_mode}.
     */
    private static DeliveryMode requestedMode(String delivery) {
        return DeliveryMode.fromValue(delivery)
                .orElseThrow(() -> new InvalidDeliveryModeException(INVALID_DELIVERY_MESSAGE));
    }

    /** The organization the process belongs to, as authorization (or bootstrap) set it on the request. */
    private static String organizationOf(IssuanceRequest request) {
        return request.organization() != null ? request.organization() : "";
    }
}
