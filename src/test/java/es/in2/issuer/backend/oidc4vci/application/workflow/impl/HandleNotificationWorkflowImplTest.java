package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationIdException;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    @Mock
    private EmailService emailService;

    @Mock
    private TransactionalOperator transactionalOperator;

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    private final String processId = "proc-123";
    private final String bearerToken = "Bearer token";
    private final String publicBaseUrl = "https://test.example/issuer";

    private UUID issuanceId;
    private Issuance issuance;

    @BeforeEach
    void setUp() {
        handleNotificationWorkflow = new HandleNotificationWorkflowImpl(
                issuanceService, revocationWorkflow,
                notificationCacheStore, enrichmentCacheStore,
                auditService, emailService, auditTrail, transactionalOperator
        );
        lenient().when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        issuanceId = UUID.randomUUID();
        issuance = mock(Issuance.class);

        lenient().when(issuance.getIssuanceId()).thenReturn(issuanceId);
    }

    @Test
    void handleNotification_accepted_draft_shouldStageNotificationReceivedWithNoResultingAction() {
        // Arrange
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getCredentialFormat()).thenReturn("jwt_vc_json");
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(enrichmentCacheStore.get(issuanceId.toString())).thenReturn(Mono.just("{\"enriched\":true}"));
        when(issuanceService.updateCredentialDataSetByIssuanceId(any(), any(), any())).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToValidByIssuanceId(issuanceId.toString())).thenReturn(Mono.empty());
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).verifyComplete();
        assertEquals(1, auditTrail.staged().size());
        AuditEntry entry = auditTrail.staged().getFirst();
        assertEquals(AuditEventType.WALLET_NOTIFICATION_RECEIVED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("credential_accepted", entry.details().get("notification_event"));
        assertEquals("None", entry.details().get("resulting_action"));
        assertEquals("issuance:" + issuanceId, entry.resource());
        assertEquals(List.of(issuanceId.toString()), auditTrail.correlationIds());
    }

    @Test
    void handleNotification_accepted_notDraft_shouldStageNothingBecauseTheNotificationIsIgnored() {
        // Arrange
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.ISSUED);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).verifyComplete();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void handleNotification_unknownNotificationId_shouldStageNothingBecauseTheNoticeIsRejected() {
        // Arrange
        when(notificationCacheStore.get("nid-9")).thenReturn(Mono.error(new IllegalStateException("not found")));
        NotificationRequest request = new NotificationRequest("nid-9", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).expectError(InvalidNotificationIdException.class).verify();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void handleNotification_failure_draft_shouldStageNotificationReceivedWithNoResultingAction() {
        // Arrange
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getEmail()).thenReturn("user@example.com");
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(emailService.sendCredentialFailureNotification(any(), any())).thenReturn(Mono.empty());
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_FAILURE, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).verifyComplete();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals("credential_failure", entry.details().get("notification_event"));
        assertEquals("None", entry.details().get("resulting_action"));
    }

    @Test
    void handleNotification_deleted_draftWithRevocationApplied_shouldStageNotificationReceivedAsRevoked() {
        // Arrange
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(issuanceService.withdrawIssuance(issuanceId.toString())).thenReturn(Mono.empty());
        when(revocationWorkflow.revokeSystem(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).verifyComplete();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals("credential_deleted", entry.details().get("notification_event"));
        assertEquals("Revoked", entry.details().get("resulting_action"));
    }

    @Test
    void handleNotification_deleted_draftWhenTheWithdrawalFails_shouldStageNothing() {
        // Arrange
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(issuanceService.withdrawIssuance(issuanceId.toString())).thenReturn(Mono.error(new IllegalStateException("db down")));
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).verifyComplete();
        assertTrue(auditTrail.all().isEmpty());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_accepted_draftWhenTheAuditEntryCannotBeStaged_shouldFailInsteadOfAnsweringSuccess() {
        // Arrange
        HandleNotificationWorkflowImpl failingAudit = new HandleNotificationWorkflowImpl(
                issuanceService, revocationWorkflow, notificationCacheStore, enrichmentCacheStore,
                auditService, emailService, new RecordingAuditTrail().failingOnStage(), transactionalOperator);
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getCredentialFormat()).thenReturn("jwt_vc_json");
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(enrichmentCacheStore.get(issuanceId.toString())).thenReturn(Mono.just("{\"enriched\":true}"));
        when(issuanceService.updateCredentialDataSetByIssuanceId(any(), any(), any())).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToValidByIssuanceId(issuanceId.toString())).thenReturn(Mono.empty());
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        // Act
        Mono<Void> handled = failingAudit.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).expectError(IllegalStateException.class).verify();
    }

    @Test
    void handleNotification_deleted_draftWhenTheStatusListCannotBeMarked_shouldNotClaimARevocation() {
        // Arrange
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(issuanceService.withdrawIssuance(issuanceId.toString())).thenReturn(Mono.empty());
        when(revocationWorkflow.revokeSystem(any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("status list unavailable")));
        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        // Act
        Mono<Void> handled = handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl);

        // Assert
        StepVerifier.create(handled).verifyComplete();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals("None", entry.details().get("resulting_action"));
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
        when(issuanceService.updateIssuanceStatusToValidByIssuanceId(issuanceId.toString()))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
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

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
                .verifyComplete();

        verify(issuanceService, never()).updateCredentialDataSetByIssuanceId(any(), any(), any());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_failure_draft_shouldSendFailureEmailAndComplete() {
        // Arrange
        String userEmail = "user@example.com";
        String eventDescription = "Timeout waiting for user decision";
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getEmail()).thenReturn(userEmail);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(emailService.sendCredentialFailureNotification(userEmail, eventDescription)).thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_FAILURE, eventDescription);

        // Act & Assert
        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
                .verifyComplete();

        verify(emailService).sendCredentialFailureNotification(userEmail, eventDescription);
        verify(issuanceService, never()).updateCredentialDataSetByIssuanceId(any(), any(), any());
        verify(issuanceService, never()).withdrawIssuance(any());
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_failure_smtpDown_shouldSwallowEmailCommunicationExceptionAndComplete() {
        // Arrange
        String userEmail = "user@example.com";
        String eventDescription = "Timeout waiting for user decision";
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getEmail()).thenReturn(userEmail);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(emailService.sendCredentialFailureNotification(userEmail, eventDescription))
                .thenReturn(Mono.error(new EmailCommunicationException("SMTP server unreachable")));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_FAILURE, eventDescription);

        // Act & Assert
        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
                .verifyComplete();

        verify(emailService).sendCredentialFailureNotification(userEmail, eventDescription);
    }

    @Test
    void handleNotification_failure_unexpectedBug_shouldSwallowExceptionAndComplete() {
        // Arrange
        String userEmail = "user@example.com";
        String eventDescription = "Timeout waiting for user decision";
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(issuance.getEmail()).thenReturn(userEmail);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString())).thenReturn(Mono.just(issuance));
        when(emailService.sendCredentialFailureNotification(userEmail, eventDescription))
                .thenReturn(Mono.error(new NullPointerException("unexpected NPE")));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_FAILURE, eventDescription);

        // Act & Assert
        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
                .verifyComplete();

        verify(emailService).sendCredentialFailureNotification(userEmail, eventDescription);
    }

    @Test
    void handleNotification_deleted_draft_shouldWithdrawAndRevokeStatusList() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));
        when(issuanceService.withdrawIssuance(issuanceId.toString()))
                .thenReturn(Mono.empty());
        when(revocationWorkflow.revokeSystem(
                processId, issuanceId.toString(), null, RevocationWorkflow.ACTOR_OID4VCI_NOTIFICATION, publicBaseUrl))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
                .verifyComplete();

        verify(issuanceService).withdrawIssuance(issuanceId.toString());
        verify(revocationWorkflow).revokeSystem(
                processId, issuanceId.toString(), null, RevocationWorkflow.ACTOR_OID4VCI_NOTIFICATION, publicBaseUrl);
    }

    @Test
    void handleNotification_deleted_notDraft_shouldBeIgnored() {
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(notificationCacheStore.get("nid-1")).thenReturn(Mono.just(issuanceId.toString()));
        when(issuanceService.getIssuanceById(issuanceId.toString()))
                .thenReturn(Mono.just(issuance));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(handleNotificationWorkflow.handleNotification(processId, request, bearerToken, publicBaseUrl))
                .verifyComplete();

        verify(issuanceService, never()).withdrawIssuance(any());
        verifyNoInteractions(revocationWorkflow);
    }
}
