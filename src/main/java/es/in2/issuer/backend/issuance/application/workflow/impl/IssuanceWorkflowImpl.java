package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

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
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, publicIssuerBaseUrl)))
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
            String publicIssuerBaseUrl) {

        return validateRequest(request, null)
                .then(Mono.defer(() -> payloadSchemaValidator.validate(request.credentialConfigurationId(), request.payload())))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, publicIssuerBaseUrl)));
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

    private Mono<IssuanceResponse> performIssuanceFlow(String processId, IssuanceRequest request,
                                                       String publicIssuerBaseUrl) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;
        String grantType = request.grantType() != null ? request.grantType() : DEFAULT_GRANT_TYPE;

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult -> {
                    UUID issuanceId = UUID.randomUUID();
                    Issuance issuance = buildIssuanceEntity(issuanceId, configId, profile.format(),
                            buildResult, request.email(), delivery);

                    return issuanceService.saveIssuance(issuance)
                            .doOnSuccess(saved -> log.info("ProcessId: {} - Created issuance: {}", processId, saved.getIssuanceId()))
                            .flatMap(saved -> credentialOfferService.createAndDeliverCredentialOffer(
                                            saved.getIssuanceId().toString(), configId, grantType, request.email(),
                                            delivery, saved.getCredentialOfferRefreshToken(),
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

    private boolean requiresIdToken(CredentialProfile profile) {
        return profile.issuancePolicy() != null
                && profile.issuancePolicy().rules() != null
                && profile.issuancePolicy().rules().contains("RequireCertificationIssuance");
    }
}
