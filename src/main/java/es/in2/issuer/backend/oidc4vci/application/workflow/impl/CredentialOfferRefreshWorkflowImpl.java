package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
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
    public Mono<Void> refreshCredentialOffer(String credentialOfferRefreshToken, String publicIssuerBaseUrl, String publicWalletBaseUrl) {
        log.info("Refreshing credential offer");

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
                        publicIssuerBaseUrl,
                        publicWalletBaseUrl))
                .flatMap(this::requireDeliveredChannel)
                .doOnSuccess(v -> log.info("Credential offer refreshed successfully"))
                .then();
    }

    /**
     * A refresh declares a single channel (email), so its failure means nothing was delivered.
     *
     * <p>Needed because {@code createAndDeliverCredentialOffer} now isolates the mail leg and reports
     * it per channel instead of erroring (EUD-33 AD-5). Without this check the isolation would turn
     * an undelivered refresh into a silent 200 — the same rule as AD-4, applied to this endpoint:
     * zero channels delivered is never a success.
     */
    private Mono<CredentialOfferResult> requireDeliveredChannel(CredentialOfferResult result) {
        String failure = result.failedModes().get(DeliveryMode.EMAIL);
        if (failure != null) {
            log.error("Credential offer refresh failed to deliver the email: {}", failure);
            return Mono.error(new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "The credential offer could not be delivered"));
        }
        return Mono.just(result);
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
