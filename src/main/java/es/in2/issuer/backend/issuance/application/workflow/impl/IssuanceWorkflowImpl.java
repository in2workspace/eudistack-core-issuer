package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
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
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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
    private final AuditService auditService;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final StatusListWorkflow statusListWorkflow;

    @Override
    @Observed(name = "issuance.issue-credential", contextualName = "issuance-issue-credential")
    public Mono<IssuanceResponse> issueCredential(
            String processId,
            IssuanceRequest request,
            String idToken,
            String publicIssuerBaseUrl) {

        var sample = issuanceMetrics.startTimer();
        String configId = request.credentialConfigurationId();
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return validateRequest(request, idToken)
                .then(Mono.defer(() -> payloadSchemaValidator.validate(configId, request.payload())))
                .then(Mono.defer(() -> issuancePdpService.authorize(configId, request.payload(), idToken)))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, idToken, publicIssuerBaseUrl, delivery)))
                .doOnSuccess(r -> {
                    issuanceMetrics.recordSuccess(sample, configId, delivery);
                    auditService.auditSuccess("credential.issued", null, "credential", configId,
                            Map.of("processId", processId, "delivery", delivery));
                })
                .doOnError(e -> issuanceMetrics.recordError(sample, configId, delivery));
    }

    @Override
    @Observed(name = "issuance.execute-bootstrap", contextualName = "issuance-execute-bootstrap")
    public Mono<IssuanceResponse> issueCredentialWithoutAuthorization(
            String processId,
            IssuanceRequest request,
            String token,
            String publicIssuerBaseUrl) {

        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;
        String safeDelivery = keepOnlyOid4vciDeliveryModes(delivery);

        return validateRequest(request, null)
                .then(Mono.defer(() -> payloadSchemaValidator.validate(request.credentialConfigurationId(), request.payload())))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, token, publicIssuerBaseUrl, safeDelivery)));
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
                                                        String publicIssuerBaseUrl, String delivery) {
        Set<DeliveryMode> modes = DeliveryMode.parse(delivery);

        boolean hasDirect  = modes.stream().anyMatch(m -> !m.isOid4vci);
        boolean hasOid4vci = modes.stream().anyMatch(m -> m.isOid4vci);

        Mono<IssuanceResponse> directMono = hasDirect
                ? performDirectIssuance(processId, request, idToken, publicIssuerBaseUrl, delivery)
                .doOnError(e -> log.error(
                        "ProcessId: {} - Direct issuance failed for credentialConfigurationId={} delivery={}",
                        processId,
                        request.credentialConfigurationId(),
                        delivery,
                        e
                ))
                : Mono.just(IssuanceResponse.builder().build());

        Mono<IssuanceResponse> oid4vciMono = hasOid4vci
                ? performOid4VciIssuance(processId, request, publicIssuerBaseUrl, extractOid4vciDelivery(modes))
                .doOnError(e -> log.error(
                        "ProcessId: {} - OID4VCI issuance failed for credentialConfigurationId={} delivery={}",
                        processId,
                        request.credentialConfigurationId(),
                        extractOid4vciDelivery(modes),
                        e
                ))
                : Mono.just(IssuanceResponse.builder().build());

        return Mono.zip(directMono, oid4vciMono, (direct, oid4vci) ->
                IssuanceResponse.builder()
                        .signedCredential(direct.signedCredential())
                        .credentialOfferUri(oid4vci.credentialOfferUri())
                        .build()
        );
    }

    private Mono<IssuanceResponse> performDirectIssuance(String processId, IssuanceRequest request, String token,
                                                          String publicIssuerBaseUrl, String originalDelivery) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String credentialFormat = profile.format() != null ? profile.format() : JWT_VC_JSON;
        StatusListFormat statusFormat = DC_SD_JWT.equals(credentialFormat)
                ? StatusListFormat.TOKEN_JWT : StatusListFormat.BITSTRING_VC;

        if (profile.cnfRequired()) {
            return Mono.error(new CredentialTypeUnsupportedException(
                    "Direct delivery is not supported for credential types that require cryptographic binding: " + configId));
        }

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
                                                        null, enrichedWithStatus, configId, credentialFormat,
                                                        null, issuanceId.toString(), request.email())
                                                .flatMap(signedCredential -> {
                                                    CredentialStatusEnum finalStatus = determineFinalStatus(buildResult);
                                                    Issuance issuance = buildDirectIssuanceEntity(
                                                            issuanceId, configId, credentialFormat,
                                                            buildResult, enrichedWithStatus,
                                                            request.email(), originalDelivery, finalStatus);
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

    private Mono<IssuanceResponse> performOid4VciIssuance(String processId, IssuanceRequest request,
                                                           String publicIssuerBaseUrl, String oid4vciDelivery) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String grantType = request.grantType() != null ? request.grantType() : DEFAULT_GRANT_TYPE;

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult -> {
                    UUID issuanceId = UUID.randomUUID();
                    Issuance issuance = buildIssuanceEntity(issuanceId, configId, profile.format(),
                            buildResult, request.email(), oid4vciDelivery);

                    return issuanceService.saveIssuance(issuance)
                            .doOnSuccess(saved -> log.debug("ProcessId: {} - Created OID4VCI issuance: {}", processId, saved.getIssuanceId()))
                            .flatMap(saved -> credentialOfferService.createAndDeliverCredentialOffer(
                                            saved.getIssuanceId().toString(), configId, grantType, request.email(),
                                            oid4vciDelivery, saved.getCredentialOfferRefreshToken(),
                                            publicIssuerBaseUrl)
                                    .map(offerResult -> IssuanceResponse.builder()
                                            .credentialOfferUri(offerResult.credentialOfferUri())
                                            .build())
                            );
                });
    }

    private Issuance buildIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                          CredentialBuildResult buildResult, String email, String delivery) {
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
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .build();
    }

    private Issuance buildDirectIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                                CredentialBuildResult buildResult, String enrichedDataSet,
                                                String email, String delivery, CredentialStatusEnum status) {
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

    private String extractOid4vciDelivery(Set<DeliveryMode> modes) {
        return modes.stream()
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
