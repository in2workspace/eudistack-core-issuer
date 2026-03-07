package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.policies.IssuancePdpService;
import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.DRAFT;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.WITHDRAWN;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SendReminderWorkflowImplTest {

    private final String processId = "processId";
    private final String issuanceId = "issuanceId";
    private final String bearerToken = "Bearer some.jwt.token";
    private final String cleanToken = "clean-token";
    private final String refreshToken = "refresh-token-123";

    @Mock private AccessTokenService accessTokenService;
    @Mock private IssuancePdpService issuancePdpService;
    @Mock private IssuanceService issuanceService;
    @Mock private CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;

    @InjectMocks
    private SendReminderWorkflowImpl sendReminderWorkflow;

    @BeforeEach
    void setup() {
        lenient().when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        lenient().when(issuancePdpService.validateSendReminder(processId, cleanToken, issuanceId))
                .thenReturn(Mono.empty());
    }

    @Test
    void sendReminder_whenDraft_refreshesCredentialOffer() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(DRAFT);
        when(issuance.getCredentialOfferRefreshToken()).thenReturn(refreshToken);

        when(issuanceService.getIssuanceById(issuanceId))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferRefreshWorkflow.refreshCredentialOffer(refreshToken))
                .thenReturn(Mono.empty());

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, issuanceId, bearerToken))
                .verifyComplete();

        verify(credentialOfferRefreshWorkflow).refreshCredentialOffer(refreshToken);
    }

    @Test
    void sendReminder_whenWithdrawn_refreshesCredentialOffer() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(WITHDRAWN);
        when(issuance.getCredentialOfferRefreshToken()).thenReturn(refreshToken);

        when(issuanceService.getIssuanceById(issuanceId))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferRefreshWorkflow.refreshCredentialOffer(refreshToken))
                .thenReturn(Mono.empty());

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, issuanceId, bearerToken))
                .verifyComplete();

        verify(credentialOfferRefreshWorkflow).refreshCredentialOffer(refreshToken);
    }

    @Test
    void sendReminder_whenNonDraftStatus_completesWithoutRefresh() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);

        when(issuanceService.getIssuanceById(issuanceId))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, issuanceId, bearerToken))
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(issuancePdpService).validateSendReminder(processId, cleanToken, issuanceId);
        verifyNoInteractions(credentialOfferRefreshWorkflow);
    }

    @Test
    void sendReminder_whenPdpDeniesAccess_failsWithAccessDenied() {
        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        when(issuancePdpService.validateSendReminder(processId, cleanToken, issuanceId))
                .thenReturn(Mono.error(new AccessDeniedException("not allowed")));
        when(issuanceService.getIssuanceById(issuanceId))
                .thenReturn(Mono.just(mock(Issuance.class)));

        StepVerifier.create(sendReminderWorkflow.sendReminder(processId, issuanceId, bearerToken))
                .expectError(AccessDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferRefreshWorkflow);
    }
}
