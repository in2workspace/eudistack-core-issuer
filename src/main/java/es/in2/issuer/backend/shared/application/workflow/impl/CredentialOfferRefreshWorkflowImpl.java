package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.GrantsService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferRefreshWorkflowImpl implements CredentialOfferRefreshWorkflow {

    private final ProcedureService procedureService;
    private final GrantsService grantsService;
    private final CredentialOfferService credentialOfferService;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final EmailService emailService;
    private final AppConfig appConfig;

    @Override
    @Observed(name = "issuance.refresh-offer", contextualName = "refresh-credential-offer")
    public Mono<Void> refreshCredentialOffer(String credentialOfferRefreshToken) {
        log.info("Refreshing credential offer for credentialOfferRefreshToken: {}", credentialOfferRefreshToken);

        return procedureService.getProcedureByCredentialOfferRefreshToken(credentialOfferRefreshToken)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Invalid or unknown credential offer refresh token")))
                .flatMap(this::validateDraftStatus)
                .flatMap(procedure -> regenerateOfferAndSendEmail(procedure, credentialOfferRefreshToken))
                .doOnSuccess(v -> log.info("Credential offer refreshed successfully for credentialOfferRefreshToken: {}", credentialOfferRefreshToken));
    }

    private Mono<Void> regenerateOfferAndSendEmail(CredentialProcedure procedure, String credentialOfferRefreshToken) {
        String procedureId = procedure.getProcedureId().toString();

        return grantsService.generateGrants("refresh", Mono.just(procedureId))
                .flatMap(grantsResult ->
                        credentialOfferService.buildCredentialOffer(
                                        procedure.getCredentialType(),
                                        grantsResult.grants(),
                                        procedure.getEmail(),
                                        grantsResult.txCodeValue())
                                .flatMap(credentialOfferCacheRepository::saveCredentialOffer)
                                .flatMap(credentialOfferService::createCredentialOfferUriResponse)
                )
                .flatMap(credentialOfferUri ->
                        procedureService.getCredentialOfferEmailInfoByProcedureId(procedureId)
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
                                            .doOnSuccess(v -> log.info("Refreshed credential offer email sent to: {}", emailInfo.email()))
                                            .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
                                })
                )
                .then();
    }

    private String buildRefreshUrl(String credentialOfferRefreshToken) {
        return UriComponentsBuilder
                .fromUriString(appConfig.getIssuerBackendUrl())
                .path("/credential-offer/refresh/" + credentialOfferRefreshToken)
                .build()
                .toUriString();
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
