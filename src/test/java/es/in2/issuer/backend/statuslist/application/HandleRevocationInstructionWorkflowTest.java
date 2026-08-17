package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.statuslist.domain.exception.RevocationInstructionInProgressException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.domain.service.StatusListPublicBaseUrlResolver;
import es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox.ClaimResult.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HandleRevocationInstructionWorkflowTest {

    @Mock
    private RevocationInstructionInbox inbox;

    @Mock
    private StatusListPublicBaseUrlResolver publicBaseUrlResolver;

    @Mock
    private RevocationWorkflow revocationWorkflow;

    @Mock
    private AuditService auditService;

    private HandleRevocationInstructionWorkflow workflow;

    private static final String PROCESS_ID = "process-123";
    private static final String MESSAGE_ID = "9d3f7c2e-4f1a-4c5b-9a0e-2b8f6d1c7e33";
    private static final String ISSUANCE_ID = "6f1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
    private static final String BASE_URL = "https://issuer.example.com";
    private static final String ACTOR = "system:revocation-instruction";

    @BeforeEach
    void setUp() {
        workflow = new HandleRevocationInstructionWorkflow(inbox, publicBaseUrlResolver, revocationWorkflow, auditService);
    }

    private RevocationInstruction instruction(String reason) {
        return new RevocationInstruction(MESSAGE_ID, "sandbox", ISSUANCE_ID, reason, Instant.now());
    }

    // ---------------------------------------------------------------- AC-01 happy path

    @Test
    void handleRevocationInstruction_claimedAndRevocable_revokesAndMarksProcessed() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "Baja voluntaria", ACTOR, BASE_URL))
                .thenReturn(Mono.empty());
        when(inbox.markProcessed(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("Baja voluntaria")))
                .verifyComplete();

        verify(inbox).markProcessed(MESSAGE_ID);
        verifyNoInteractions(auditService);
    }

    // ---------------------------------------------------------------- AC-03/AC-04 reason presence

    @Test
    void handleRevocationInstruction_reasonAbsent_stillRevokesWithNullReason() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, ACTOR, BASE_URL))
                .thenReturn(Mono.empty());
        when(inbox.markProcessed(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction(null)))
                .verifyComplete();

        verify(revocationWorkflow).revokeSystem(PROCESS_ID, ISSUANCE_ID, null, ACTOR, BASE_URL);
    }

    // ---------------------------------------------------------------- AC-05 idempotency

    @Test
    void handleRevocationInstruction_alreadyProcessed_isNoopWithoutTouchingDomain() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(ALREADY_PROCESSED));

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason")))
                .verifyComplete();

        verifyNoInteractions(publicBaseUrlResolver, revocationWorkflow, auditService);
        verify(inbox, never()).markProcessed(any());
        verify(inbox, never()).markSkipped(any());
    }

    // ---------------------------------------------------------------- EC-03 in-flight overlap

    @Test
    void handleRevocationInstruction_inProgress_propagatesRetryableError() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(IN_PROGRESS));

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason")))
                .expectError(RevocationInstructionInProgressException.class)
                .verify();

        verifyNoInteractions(publicBaseUrlResolver, revocationWorkflow, auditService);
    }

    // ---------------------------------------------------------------- AC-06 no-op: not revocable

    @Test
    void handleRevocationInstruction_invalidStatus_isSkippedWithAuditAndAck() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL))
                .thenReturn(Mono.error(new InvalidStatusException("Invalid status: REVOKED")));
        when(inbox.markSkipped(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason")))
                .verifyComplete();

        verify(inbox).markSkipped(MESSAGE_ID);
        verify(inbox, never()).markProcessed(any());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditSuccess(eq("credential.revoke.skipped"), eq(ACTOR), eq("credential"),
                eq(ISSUANCE_ID), details.capture());
        assertThat(details.getValue()).containsEntry("outcome", "noop");
    }

    // ---------------------------------------------------------------- ES-03 conflict of state

    @Test
    void handleRevocationInstruction_concurrentTransitionConflict_isSkippedWithAudit() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL))
                .thenReturn(Mono.error(new InvalidCredentialStatusTransitionException(
                        CredentialStatusEnum.REVOKED, CredentialStatusEnum.REVOKED)));
        when(inbox.markSkipped(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason")))
                .verifyComplete();

        verify(inbox).markSkipped(MESSAGE_ID);
    }

    // ---------------------------------------------------------------- fail-closed propagation (AD-2, ES-01/02/04)

    @Test
    void handleRevocationInstruction_baseUrlNotResolvable_propagatesErrorWithoutSkipping() {
        RuntimeException fatal = new RuntimeException("fail-closed: base URL not resolvable");
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.error(fatal));

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason")))
                .expectErrorMatches(e -> e == fatal)
                .verify();

        verify(inbox, never()).markSkipped(any());
        verify(inbox, never()).markProcessed(any());
    }

    // ---------------------------------------------------------------- AC-02 audit resilience

    @Test
    void handleRevocationInstruction_auditSkippedThrows_stillMarksSkipped() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL))
                .thenReturn(Mono.error(new InvalidStatusException("Invalid status: REVOKED")));
        doThrow(new RuntimeException("audit sink down"))
                .when(auditService).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyMap());
        when(inbox.markSkipped(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason")))
                .verifyComplete();

        verify(inbox).markSkipped(MESSAGE_ID);
    }
}
