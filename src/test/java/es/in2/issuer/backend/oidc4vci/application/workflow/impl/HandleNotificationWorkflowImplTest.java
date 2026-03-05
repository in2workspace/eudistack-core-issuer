package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HandleNotificationWorkflowImplTest {

    @InjectMocks
    private HandleNotificationWorkflowImpl handleNotificationWorkflow;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private RevocationWorkflow revocationWorkflow;

    private final String processId = "proc-123";
    private final String bearerToken = "Bearer token";

    private UUID procedureId;
    private CredentialProcedure procedure;

    @BeforeEach
    void setUp() {
        procedureId = UUID.randomUUID();
        UUID notificationId = UUID.randomUUID();
        procedure = mock(CredentialProcedure.class);

        when(procedure.getProcedureId()).thenReturn(procedureId);
        when(procedure.getNotificationId()).thenReturn(notificationId);
    }

    @Test
    void handleNotification_idempotent_shouldDoNothing_andNotRevoke() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-1");
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_nonDeletedEvent_shouldNotRevoke_evenIfNotIdempotent() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);
        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-1");
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_deletedEvent_shouldRevoke_whenNotIdempotent() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));
        when(revocationWorkflow.revokeSystem(processId, bearerToken, procedureId.toString()))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(revocationWorkflow).revokeSystem(processId, bearerToken, procedureId.toString());
    }

    @Test
    void handleNotification_deletedEvent_revokeFails_shouldPropagateError() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));
        when(revocationWorkflow.revokeSystem(processId, bearerToken, procedureId.toString()))
                .thenReturn(Mono.error(new RuntimeException("revocation failed")));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .expectError(RuntimeException.class)
                .verify();
    }
}
