package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import io.micrometer.observation.annotation.Observed;
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

    private static final String DEFAULT_GRANT_TYPE = "authorization_code";

    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;

    @Override
    @Observed(name = "issuance.refresh-offer", contextualName = "refresh-credential-offer")
    public Mono<Void> refreshCredentialOffer(String credentialOfferRefreshToken, String publicIssuerBaseUrl) {
        log.info("Refreshing credential offer for credentialOfferRefreshToken: {}", credentialOfferRefreshToken);

        return issuanceService.getIssuanceByCredentialOfferRefreshToken(credentialOfferRefreshToken)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Invalid or unknown credential offer refresh token")))
                .flatMap(this::validateDraftStatus)
                .flatMap(issuance -> credentialOfferService.createAndDeliverCredentialOffer(
                        issuance.getIssuanceId().toString(),
                        issuance.getCredentialType(),
                        DEFAULT_GRANT_TYPE,
                        issuance.getEmail(),
                        DeliveryMode.EMAIL.value,
                        credentialOfferRefreshToken,
                        publicIssuerBaseUrl))
                .doOnSuccess(v -> log.info("Credential offer refreshed successfully for credentialOfferRefreshToken: {}", credentialOfferRefreshToken))
                .then();
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
