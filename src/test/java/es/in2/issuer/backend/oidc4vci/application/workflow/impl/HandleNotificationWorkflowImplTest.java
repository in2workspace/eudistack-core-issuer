package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
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
    private IssuanceService issuanceService;

    @Mock
    private RevocationWorkflow revocationWorkflow;

    @Mock
    private TransientStore<String> notificationCacheStore;

    @Mock
    private TransientStore<String> enrichmentCacheStore;

    @Mock
    private AuditService auditService;

    private final String processId = "proc-123";
    private final String bearerToken = "Bearer token";

    private UUID issuanceId;
    private Issuance issuance;

    @BeforeEach
    void setUp() {
        handleNotificationWorkflow = new HandleNotificationWorkflowImpl(
                issuanceService, revocationWorkflow,
                notificationCacheStore, enrichmentCacheStore,
                auditService
        );

        issuanceId = UUID.randomUUID();
        issuance = mock(Issuance.class);

        when(issuance.getIssuanceId()).thenReturn(issuanceId);
    }

    @Test
    void handleNotification_accepted_draft_shouldPersistEnrichedDataAndTransitionToIssued() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getCredentialFormat()).thenReturn("jwt_vc_json");
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));
        when(enrichmentCacheStore.get(issuanceId.toString())).thenReturn(Mono.just("{\"enriched\":true}"));
        when(issuanceService.updateCredentialDataSetByIssuanceId(
                issuanceId.toString(), "{\"enriched\":true}", "jwt_vc_json"))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(issuanceService).updateCredentialDataSetByIssuanceId(
                issuanceId.toString(), "{\"enriched\":true}", "jwt_vc_json");
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_accepted_notDraft_shouldBeIgnored() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.ISSUED);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(issuanceService, never()).updateCredentialDataSetByIssuanceId(any(), any(), any());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_failure_draft_shouldLogOnlyAndStayDraft() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_FAILURE, "wallet error");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(issuanceService, never()).updateCredentialDataSetByIssuanceId(any(), any(), any());
        verify(issuanceService, never()).withdrawIssuance(any());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_deleted_draft_shouldWithdrawAndRevokeStatusList() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));
        when(issuanceService.withdrawIssuance(issuanceId.toString()))
                .thenReturn(Mono.empty());
        when(revocationWorkflow.revokeSystem(processId, bearerToken, issuanceId.toString()))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(issuanceService).withdrawIssuance(issuanceId.toString());
        verify(revocationWorkflow).revokeSystem(processId, bearerToken, issuanceId.toString());
    }

    @Test
    void handleNotification_deleted_notDraft_shouldBeIgnored() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(issuanceService, never()).withdrawIssuance(any());
        verifyNoInteractions(revocationWorkflow);
    }
}
