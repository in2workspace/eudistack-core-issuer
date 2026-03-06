package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.IssuancePdpService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuanceWorkflowImpl implements IssuanceWorkflow {

    private final CredentialDataSetBuilderService credentialDataSetBuilderService;
    private final ProcedureService procedureService;
    private final GrantsService grantsService;
    private final CredentialOfferService credentialOfferService;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final EmailService emailService;
    private final AppConfig appConfig;
    private final IssuancePdpService issuancePdpService;
    private final PayloadSchemaValidator payloadSchemaValidator;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final IssuanceMetrics issuanceMetrics;

    @Override
    @Observed(name = "issuance.execute", contextualName = "issuance-execute")
    public Mono<IssuanceResponse> execute(
            String processId,
            PreSubmittedCredentialDataRequest request,
            String idToken) {

        var sample = issuanceMetrics.startTimer();
        String configId = request.credentialConfigurationId();
        String delivery = request.delivery() != null ? request.delivery() : DELIVERY_EMAIL;

        return validateRequest(request, idToken)
                .then(payloadSchemaValidator.validate(configId, request.payload()))
                .then(issuancePdpService.authorize(configId, request.payload(), idToken))
                .then(issueCredential(processId, request))
                .doOnSuccess(r -> issuanceMetrics.recordSuccess(sample, configId, delivery))
                .doOnError(e -> issuanceMetrics.recordError(sample, configId, delivery));
    }

    @Override
    @Observed(name = "issuance.execute-bootstrap", contextualName = "issuance-execute-bootstrap")
    public Mono<IssuanceResponse> executeWithoutAuthorization(
            String processId,
            PreSubmittedCredentialDataRequest request) {

        return validateRequest(request, null)
                .then(payloadSchemaValidator.validate(request.credentialConfigurationId(), request.payload()))
                .then(issueCredential(processId, request));
    }

    private Mono<Void> validateRequest(PreSubmittedCredentialDataRequest request, String idToken) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(request.credentialConfigurationId());
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(
                    "Unknown credential_configuration_id: " + request.credentialConfigurationId()));
        }
        if (profile.credentialType().equals(LABEL_CREDENTIAL) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException(
                    "Missing required ID Token header for VerifiableCertification issuance."));
        }
        return Mono.empty();
    }

    /**
     * Orchestrates the issuance flow:
     * 1. Build credential dataset (business data only, no issuer/cnf/statusList)
     * 2. Create procedure (DRAFT) with format, delivery, and credentialOfferRefreshToken
     * 3. Generate both grants (pre-auth + auth-code) — cache stores preAuthCode → {procedureId, txCode}
     * 4. Build and cache credential offer
     * 5. Deliver (email or UI)
     */
    private Mono<IssuanceResponse> issueCredential(String processId, PreSubmittedCredentialDataRequest request) {
        String procedureId = UUID.randomUUID().toString();

        return credentialDataSetBuilderService.buildDataSet(procedureId, request)
                .flatMap(creationRequest ->
                        procedureService.createCredentialProcedure(creationRequest)
                                .flatMap(savedProcedure -> {
                                    String savedProcedureId = savedProcedure.getProcedureId().toString();
                                    String credentialOfferRefreshToken = savedProcedure.getCredentialOfferRefreshToken();
                                    log.info("ProcessId: {} - Created procedure: {}", processId, savedProcedureId);

                                    return grantsService.generateGrants(processId, Mono.just(savedProcedureId))
                                            .flatMap(grantsResult ->
                                                    buildOfferAndDeliver(grantsResult, creationRequest, savedProcedureId, credentialOfferRefreshToken)
                                            );
                                })
                );
    }

    private Mono<IssuanceResponse> buildOfferAndDeliver(
            GrantsResult grantsResult,
            CredentialProcedureCreationRequest creationRequest,
            String procedureId,
            String credentialOfferRefreshToken) {

        return credentialOfferService.buildCredentialOffer(
                        creationRequest.credentialType(),
                        grantsResult.grants(),
                        creationRequest.email(),
                        grantsResult.txCodeValue()
                )
                .flatMap(credentialOfferCacheRepository::saveCredentialOffer)
                .flatMap(credentialOfferService::createCredentialOfferUriResponse)
                .flatMap(credentialOfferUri -> {
                    if (DELIVERY_UI.equals(creationRequest.delivery())) {
                        log.info("Delivering credential offer via UI for procedure: {}", procedureId);
                        return Mono.just(IssuanceResponse.builder()
                                .credentialOfferUri(credentialOfferUri)
                                .build());
                    }

                    log.info("Delivering credential offer via email for procedure: {}", procedureId);
                    return procedureService.getCredentialOfferEmailInfoByProcedureId(procedureId)
                            .flatMap(emailInfo -> {
                                String refreshUrl = buildRefreshUrl(credentialOfferRefreshToken);
                                return emailService.sendCredentialOfferEmail(
                                                emailInfo.email(),
                                                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                                credentialOfferUri,
                                                refreshUrl,
                                                appConfig.getWalletFrontendUrl(),
                                                emailInfo.organization()
                                        )
                                        .doOnSuccess(v -> log.info("Credential offer email sent for procedureId={}", creationRequest.procedureId()))
                                        .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                                        .thenReturn(IssuanceResponse.builder().build());
                            });
                });
    }

    private String buildRefreshUrl(String credentialOfferRefreshToken) {
        return UriComponentsBuilder
                .fromUriString(appConfig.getIssuerBackendUrl())
                .path("/credential-offer/refresh/" + credentialOfferRefreshToken)
                .build()
                .toUriString();
    }

}
