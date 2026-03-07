package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.application.workflow.SendReminderWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SendReminderControllerTest {

    @Mock
    private SendReminderWorkflow sendReminderWorkflow;

    @InjectMocks
    private SendReminderController sendReminderController;

    @Test
    void sendEmailNotification_completesSuccessfully() {
        // Arrange
        String authorizationHeader = "Bearer some.jwt.token";
        String issuanceId = "testProcedureId";

        when(sendReminderWorkflow.sendReminder(anyString(), eq(issuanceId), eq(authorizationHeader)))
                .thenReturn(Mono.empty());

        // Act
        Mono<Void> result = sendReminderController.sendEmailReminder(authorizationHeader, issuanceId);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();

        verify(sendReminderWorkflow).sendReminder(anyString(), eq(issuanceId), eq(authorizationHeader));
    }
}
