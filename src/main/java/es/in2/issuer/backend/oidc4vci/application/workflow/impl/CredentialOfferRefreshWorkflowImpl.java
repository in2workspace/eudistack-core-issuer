package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import io.micrometer.observation.annotation.Observed;

import static es.in2.issuer.backend.shared.domain.util.Constants.AUTHORIZATION_CODE;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferRefreshWorkflowImpl implements CredentialOfferRefreshWorkflow {

    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;

    @Override
    @Observed(name = "issuance.refresh-offer", contextualName = "refresh-credential-offer")
    public Mono<Void> refreshCredentialOffer(String credentialOfferRefreshToken, String publicIssuerBaseUrl, String publicWalletBaseUrl) {
        log.info("Refreshing credential offer");

        return mintOffer(credentialOfferRefreshToken, DeliveryMode.EMAIL.value, publicIssuerBaseUrl, publicWalletBaseUrl)
                .flatMap(result -> result.emailError() != null
                        ? Mono.<CredentialOfferResult>error(new EmailCommunicationException(result.emailError()))
                        : Mono.just(result))
                .doOnSuccess(v -> log.info("Credential offer refreshed successfully"))
                .then();
    }

    @Override
    @Observed(name = "issuance.refresh-offer-uri", contextualName = "refresh-credential-offer-uri")
    public Mono<String> refreshCredentialOfferUri(String credentialOfferRefreshToken, String publicIssuerBaseUrl, String publicWalletBaseUrl) {
        log.info("Refreshing credential offer URI");

        return mintOffer(credentialOfferRefreshToken, DeliveryMode.UI.value, publicIssuerBaseUrl, publicWalletBaseUrl)
                .map(CredentialOfferResult::credentialOfferUri)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY, "The issuer produced no credential offer URI")))
                .doOnSuccess(uri -> log.info("Credential offer URI refreshed successfully"));
    }

    private Mono<CredentialOfferResult> mintOffer(String credentialOfferRefreshToken, String deliveryMode,
                                                  String publicIssuerBaseUrl, String publicWalletBaseUrl) {
        return issuanceService.getIssuanceByCredentialOfferRefreshToken(credentialOfferRefreshToken)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Invalid or unknown credential offer refresh token")))
                .flatMap(this::validateDraftStatus)
                .flatMap(issuance -> {
                    String grantType = issuance.getGrantType() != null
                            ? issuance.getGrantType()
                            : AUTHORIZATION_CODE;
                    return credentialOfferService.createAndDeliverCredentialOffer(
                            issuance.getIssuanceId().toString(),
                            issuance.getCredentialType(),
                            grantType,
                            issuance.getEmail(),
                            deliveryMode,
                            credentialOfferRefreshToken,
                            publicIssuerBaseUrl,
                            publicWalletBaseUrl);
                });
    }

    private Mono<Issuance> validateDraftStatus(Issuance issuance) {
        if (issuance.getCredentialStatus() != CredentialStatusEnum.DRAFT) {
            log.warn("Refresh rejected: procedure {} is in status {}", issuance.getIssuanceId(), issuance.getCredentialStatus());
            return Mono.error(new ResponseStatusException(
                    HttpStatus.GONE, "This credential offer can no longer be refreshed"));
        }
        return Mono.just(issuance);
    }
}
