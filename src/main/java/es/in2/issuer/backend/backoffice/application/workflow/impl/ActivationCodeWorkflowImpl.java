package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferGrants;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeGrant;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_ACTIVATION_EMAIL_SUBJECT;
import static es.in2.issuer.backend.shared.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;

@Slf4j
@Service
@RequiredArgsConstructor
public class ActivationCodeWorkflowImpl implements ActivationCodeWorkflow {

    private final CredentialOfferService credentialOfferService;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;
    private final EmailService emailService;
    private final IssuerProperties issuerProperties;

    @Override
    public Mono<CredentialOfferUriResponse> buildCredentialOfferUri(String processId, String transactionCode) {
        return deferredCredentialMetadataService.validateTransactionCode(transactionCode)
                .then(Mono.just(transactionCode))
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    @Override
    public Mono<CredentialOfferUriResponse> buildNewCredentialOfferUri(String processId, String cTransactionCode) {
        return deferredCredentialMetadataService.validateCTransactionCode(cTransactionCode)
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    private Mono<CredentialOfferUriResponse> buildCredentialOfferUriInternal(String transactionCode) {
        return deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode)
                .flatMap(procedureId ->
                        credentialProcedureService.getCredentialProcedureById(procedureId)
                                .flatMap(credentialProcedure ->
                                        preAuthorizedCodeWorkflow.generatePreAuthorizedCode(Mono.just(procedureId))
                                                .flatMap(preAuthResponse ->
                                                        deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
                                                                        transactionCode,
                                                                        preAuthResponse.preAuthorizedCode()
                                                                )
                                                                .then(Mono.defer(() -> {
                                                                    CredentialOfferGrants grants = toCredentialOfferGrants(preAuthResponse);
                                                                    return credentialOfferService.buildCredentialOffer(
                                                                                    credentialProcedure.getCredentialType(),
                                                                                    grants,
                                                                                    credentialProcedure.getEmail(),
                                                                                    preAuthResponse.pin()
                                                                            )
                                                                            .flatMap(credentialOfferCacheRepository::saveCustomCredentialOffer)
                                                                            .flatMap(credentialOfferService::createCredentialOfferUriResponse);
                                                                }))
                                                )
                                                .flatMap(credentialOfferUri ->
                                                        deferredCredentialMetadataService.updateCacheStoreForCTransactionCode(transactionCode)
                                                                .map(cTransactionCodeMap ->
                                                                        CredentialOfferUriResponse.builder()
                                                                                .credentialOfferUri(credentialOfferUri)
                                                                                .cTransactionCode(cTransactionCodeMap.get("cTransactionCode").toString())
                                                                                .cTransactionCodeExpiresIn(Integer.parseInt(cTransactionCodeMap.get("cTransactionCodeExpiresIn").toString()))
                                                                                .build()
                                                                )
                                                )
                                )
                );
    }

    @Override
    public Mono<Void> reissueCredentialOffer(String processId, String transactionCode) {
        log.info("[{}] Reissuing credential offer for transactionCode", processId);
        return deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode)
                .flatMap(procedureId ->
                        credentialProcedureService.getCredentialProcedureById(procedureId)
                                .zipWith(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                                .flatMap(tuple -> {
                                    var credentialProcedure = tuple.getT1();
                                    var emailInfo = tuple.getT2();
                                    return preAuthorizedCodeWorkflow.generatePreAuthorizedCode(Mono.just(procedureId))
                                            .flatMap(preAuthResponse -> {
                                                CredentialOfferGrants grants = toCredentialOfferGrants(preAuthResponse);
                                                return deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
                                                                transactionCode, preAuthResponse.preAuthorizedCode()
                                                        )
                                                        .then(credentialOfferService.buildCredentialOffer(
                                                                credentialProcedure.getCredentialType(),
                                                                grants,
                                                                emailInfo.email(),
                                                                preAuthResponse.pin()
                                                        ))
                                                        .flatMap(credentialOfferCacheRepository::saveCustomCredentialOffer)
                                                        .flatMap(credentialOfferService::createCredentialOfferUriResponse)
                                                        .flatMap(credentialOfferUri -> {
                                                            String reissueUrl = buildReissueUrl(transactionCode);
                                                            return emailService.sendCredentialOfferEmail(
                                                                    emailInfo.email(),
                                                                    CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                                                    credentialOfferUri,
                                                                    reissueUrl,
                                                                    issuerProperties.getWalletFrontendUrl(),
                                                                    emailInfo.organization()
                                                            );
                                                        });
                                            });
                                })
                )
                .onErrorMap(ex -> !(ex instanceof EmailCommunicationException),
                        ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    private CredentialOfferGrants toCredentialOfferGrants(PreAuthorizedCodeResponse preAuthResponse) {
        PreAuthorizedCodeGrant preAuthGrant = PreAuthorizedCodeGrant.builder()
                .preAuthorizedCode(preAuthResponse.preAuthorizedCode())
                .txCode(preAuthResponse.txCode())
                .build();
        return CredentialOfferGrants.builder()
                .preAuthorizedCode(preAuthGrant)
                .build();
    }

    private String buildReissueUrl(String transactionCode) {
        return UriComponentsBuilder
                .fromUriString(issuerProperties.getIssuerBackendUrl())
                .path("/oid4vci/v1/credential-offer/reissue/" + transactionCode)
                .build()
                .toUriString();
    }

}
