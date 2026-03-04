package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.application.workflow.SendReminderWorkflow;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_READY;

@Slf4j
@Service
@RequiredArgsConstructor
public class SendReminderWorkflowImpl implements SendReminderWorkflow {

    private final AccessTokenService accessTokenService;
    private final BackofficePdpService backofficePdpService;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final ActivationCodeWorkflow activationCodeWorkflow;

    @Override
    public Mono<Void> sendReminder(String processId, String procedureId, String bearerToken) {
        log.info("sendReminder processId={} procedureId={}", processId, procedureId);

        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> backofficePdpService.validateSendReminder(processId, token, procedureId)
                        .then(credentialProcedureService.getCredentialProcedureById(procedureId))
                )
                .flatMap(credentialProcedure ->
                    switch (credentialProcedure.getCredentialStatus()) {
                        case DRAFT, WITHDRAWN ->
                            // Refresh the transaction code and reissue a credential offer via email
                            deferredCredentialMetadataService
                                    .updateTransactionCodeInDeferredCredentialMetadata(procedureId)
                                    .flatMap(newTransactionCode ->
                                            activationCodeWorkflow.reissueCredentialOffer(processId, newTransactionCode)
                                    );

                        case PEND_DOWNLOAD ->
                            emailService.sendCredentialSignedNotification(
                                    credentialProcedure.getEmail(),
                                    CREDENTIAL_READY,
                                    "email.you-can-use-wallet"
                            );

                        default -> Mono.empty();
                    }
                )
                .then();
    }
}
