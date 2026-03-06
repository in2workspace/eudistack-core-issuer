package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.SendReminderWorkflow;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class SendReminderWorkflowImpl implements SendReminderWorkflow {

    private final AccessTokenService accessTokenService;
    private final BackofficePdpService backofficePdpService;
    private final ProcedureService procedureService;
    private final CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;

    @Override
    public Mono<Void> sendReminder(String processId, String procedureId, String bearerToken) {
        log.info("sendReminder processId={} procedureId={}", processId, procedureId);

        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> backofficePdpService.validateSendReminder(processId, token, procedureId)
                        .then(procedureService.getProcedureById(procedureId))
                )
                .flatMap(credentialProcedure ->
                    switch (credentialProcedure.getCredentialStatus()) {
                        case DRAFT ->
                            credentialOfferRefreshWorkflow.refreshCredentialOffer(
                                    credentialProcedure.getCredentialOfferRefreshToken());

                        default -> Mono.empty();
                    }
                )
                .then();
    }
}
