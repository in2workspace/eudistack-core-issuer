package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.DeliveryService;
import es.in2.issuer.backend.shared.domain.service.GrantsService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.DELIVERY_EMAIL;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferRefreshWorkflowImpl implements CredentialOfferRefreshWorkflow {

    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final GrantsService grantsService;
    private final CredentialOfferService credentialOfferService;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final DeliveryService deliveryService;

    @Override
    @Observed(name = "issuance.refresh-offer", contextualName = "refresh-credential-offer")
    public Mono<Void> refreshCredentialOffer(String refreshToken) {
        log.info("Refreshing credential offer for refreshToken: {}", refreshToken);

        return credentialProcedureService.getCredentialProcedureByRefreshToken(refreshToken)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Invalid or unknown refresh token")))
                .flatMap(this::validateDraftStatus)
                .flatMap(procedure -> regenerateOfferAndDeliver(procedure, refreshToken))
                .doOnSuccess(v -> log.info("Credential offer refreshed successfully for refreshToken: {}", refreshToken));
    }

    private Mono<Void> regenerateOfferAndDeliver(CredentialProcedure procedure, String refreshToken) {
        String procedureId = procedure.getProcedureId().toString();

        return deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId)
                .flatMap(transactionCode ->
                        grantsService.generateGrants("refresh", Mono.just(procedureId))
                                .flatMap(grantsResult ->
                                        deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
                                                        transactionCode, grantsResult.grants().preAuthorizedCode().preAuthorizedCode())
                                                .then(credentialOfferService.buildCredentialOffer(
                                                        procedure.getCredentialType(),
                                                        grantsResult.grants(),
                                                        procedure.getEmail(),
                                                        grantsResult.txCodeValue()))
                                                .flatMap(credentialOfferCacheRepository::saveCustomCredentialOffer)
                                                .flatMap(credentialOfferService::createCredentialOfferUriResponse)
                                )
                )
                .flatMap(credentialOfferUri ->
                        credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId)
                                .flatMap(emailInfo -> deliveryService.deliver(
                                        DELIVERY_EMAIL, credentialOfferUri, refreshToken, emailInfo))
                )
                .then();
    }

    private Mono<CredentialProcedure> validateDraftStatus(CredentialProcedure procedure) {
        if (procedure.getCredentialStatus() != CredentialStatusEnum.DRAFT) {
            log.warn("Refresh rejected: procedure {} is in status {}", procedure.getProcedureId(), procedure.getCredentialStatus());
            return Mono.error(new ResponseStatusException(
                    HttpStatus.GONE, "This credential offer can no longer be refreshed"));
        }
        return Mono.just(procedure);
    }

}
