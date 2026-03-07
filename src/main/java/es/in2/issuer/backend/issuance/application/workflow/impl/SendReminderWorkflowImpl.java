package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.SendReminderWorkflow;
import es.in2.issuer.backend.issuance.application.workflow.policies.IssuancePdpService;
import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class SendReminderWorkflowImpl implements SendReminderWorkflow {

    private final AccessTokenService accessTokenService;
    private final IssuancePdpService issuancePdpService;
    private final IssuanceService issuanceService;
    private final CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;

    @Override
    public Mono<Void> sendReminder(String processId, String issuanceId, String bearerToken) {
        log.info("sendReminder processId={} issuanceId={}", processId, issuanceId);

        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> issuancePdpService.validateSendReminder(processId, token, issuanceId)
                        .then(issuanceService.getIssuanceById(issuanceId))
                )
                .flatMap(issuance ->
                    switch (issuance.getCredentialStatus()) {
                        case DRAFT, WITHDRAWN ->
                            credentialOfferRefreshWorkflow.refreshCredentialOffer(
                                    issuance.getCredentialOfferRefreshToken());

                        default -> Mono.empty();
                    }
                )
                .then();
    }
}
