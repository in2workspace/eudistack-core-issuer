package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_READY;
import static es.in2.issuer.backend.shared.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.DRAFT;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_DOWNLOAD;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.WITHDRAWN;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SendReminderWorkflowImplTest {

    private final String processId = "processId";
    private final String procedureId = "procedureId";
    private final String bearerToken = "Bearer some.jwt.token";
    private final String cleanToken = "clean-token";

    private final String issuerUiExternalDomain = "https://example.com";
    private final String knowledgebaseWalletUrl = "https://knowledgebaseUrl.com";

    private final String transactionCode = "transactionCode123";
    private final String email = "owner@example.com";

    @Mock private IssuerProperties issuerProperties;
    @Mock private AccessTokenService accessTokenService;
    @Mock private BackofficePdpService backofficePdpService;
    @Mock private EmailService emailService;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock private ActivationCodeWorkflow activationCodeWorkflow;

    @InjectMocks
    private SendReminderWorkflowImpl sendReminderWorkflow;

    @BeforeEach
    void setup() {
        lenient().when(issuerProperties.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        lenient().when(issuerProperties.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);

        lenient().when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        lenient().when(backofficePdpService.validateSendReminder(processId, cleanToken, procedureId))
                .thenReturn(Mono.empty());
    }

    @Test
    void sendReminder_whenDraft_sendsActivationEmail() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(DRAFT);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(activationCodeWorkflow.reissueCredentialOffer(processId, transactionCode))
                .thenReturn(Mono.empty());

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, procedureId, bearerToken))
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateSendReminder(processId, cleanToken, procedureId);
        verify(activationCodeWorkflow).reissueCredentialOffer(processId, transactionCode);
    }

    @Test
    void sendReminder_whenWithdrawn_sendsActivationEmail() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(WITHDRAWN);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(activationCodeWorkflow.reissueCredentialOffer(processId, transactionCode))
                .thenReturn(Mono.empty());

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, procedureId, bearerToken))
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateSendReminder(processId, cleanToken, procedureId);
        verify(activationCodeWorkflow).reissueCredentialOffer(processId, transactionCode);
    }

    @Test
    void sendReminder_whenDraft_emailFailure_mapsToEmailCommunicationException() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(DRAFT);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(activationCodeWorkflow.reissueCredentialOffer(processId, transactionCode))
                .thenReturn(Mono.error(new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE)));

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, procedureId, bearerToken))
                .expectErrorMatches(ex -> ex instanceof EmailCommunicationException &&
                        ex.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .verify();
    }

    @Test
    void sendReminder_whenPendDownload_sendsSignedNotification() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(PEND_DOWNLOAD);
        when(credentialProcedure.getEmail()).thenReturn(email);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(emailService.sendCredentialSignedNotification(
                email,
                CREDENTIAL_READY,
                "email.you-can-use-wallet")
        ).thenReturn(Mono.empty());

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, procedureId, bearerToken))
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateSendReminder(processId, cleanToken, procedureId);
        verify(emailService, times(1))
                .sendCredentialSignedNotification(email, CREDENTIAL_READY, "email.you-can-use-wallet");
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendReminder_whenPdpDeniesAccess_failsWithAccessDenied() {
        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        when(backofficePdpService.validateSendReminder(processId, cleanToken, procedureId))
                .thenReturn(Mono.error(new AccessDeniedException("not allowed")));
        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(mock(CredentialProcedure.class)));

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, procedureId, bearerToken))
                .expectError(AccessDeniedException.class)
                .verify();

        verifyNoInteractions(emailService);
    }
}
