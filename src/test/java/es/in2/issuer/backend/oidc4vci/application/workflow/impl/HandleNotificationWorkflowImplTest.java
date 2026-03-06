package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HandleNotificationWorkflowImplTest {

    private HandleNotificationWorkflowImpl handleNotificationWorkflow;

    @Mock
    private ProcedureService procedureService;

    @Mock
    private RevocationWorkflow revocationWorkflow;

    @Mock
    private CacheStore<String> notificationCacheStore;

    @Mock
    private CacheStore<String> enrichmentCacheStore;

    @Mock
    private AuditService auditService;

    private final String processId = "proc-123";
    private final String bearerToken = "Bearer token";

    private UUID procedureId;
    private CredentialProcedure procedure;

    @BeforeEach
    void setUp() {
        handleNotificationWorkflow = new HandleNotificationWorkflowImpl(
                procedureService, revocationWorkflow,
                notificationCacheStore, enrichmentCacheStore,
                auditService
        );

        procedureId = UUID.randomUUID();
        procedure = mock(CredentialProcedure.class);

        when(procedure.getProcedureId()).thenReturn(procedureId);
    }

    @Test
    void handleNotification_accepted_draft_shouldPersistEnrichedDataAndTransitionToIssued() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(procedure.getCredentialFormat()).thenReturn("jwt_vc_json");
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(procedureId.toString()));
        when(procedureService.getProcedureById(procedureId.toString()))
                .thenReturn(Mono.just(procedure));
        when(enrichmentCacheStore.get(procedureId.toString())).thenReturn(Mono.just("{\"enriched\":true}"));
        when(procedureService.updateCredentialDataSetByProcedureId(
                procedureId.toString(), "{\"enriched\":true}", "jwt_vc_json"))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(procedureService).updateCredentialDataSetByProcedureId(
                procedureId.toString(), "{\"enriched\":true}", "jwt_vc_json");
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_accepted_notDraft_shouldBeIgnored() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.ISSUED);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(procedureId.toString()));
        when(procedureService.getProcedureById(procedureId.toString()))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(procedureService, never()).updateCredentialDataSetByProcedureId(any(), any(), any());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_failure_draft_shouldLogOnlyAndStayDraft() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(procedureId.toString()));
        when(procedureService.getProcedureById(procedureId.toString()))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_FAILURE, "wallet error");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(procedureService, never()).updateCredentialDataSetByProcedureId(any(), any(), any());
        verify(procedureService, never()).withdrawCredentialProcedure(any());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_deleted_draft_shouldWithdrawAndRevokeStatusList() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(procedureId.toString()));
        when(procedureService.getProcedureById(procedureId.toString()))
                .thenReturn(Mono.just(procedure));
        when(procedureService.withdrawCredentialProcedure(procedureId.toString()))
                .thenReturn(Mono.empty());
        when(revocationWorkflow.revokeSystem(processId, bearerToken, procedureId.toString()))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(procedureService).withdrawCredentialProcedure(procedureId.toString());
        verify(revocationWorkflow).revokeSystem(processId, bearerToken, procedureId.toString());
    }

    @Test
    void handleNotification_deleted_notDraft_shouldBeIgnored() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(procedureId.toString()));
        when(procedureService.getProcedureById(procedureId.toString()))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(procedureService, never()).withdrawCredentialProcedure(any());
        verifyNoInteractions(revocationWorkflow);
    }
}
