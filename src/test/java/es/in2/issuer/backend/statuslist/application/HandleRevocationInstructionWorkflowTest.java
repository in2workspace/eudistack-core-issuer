package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.statuslist.domain.exception.RevocationInstructionInProgressException;
import es.in2.issuer.backend.statuslist.domain.exception.TenantBindingMismatchException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.domain.model.TenantBindingResolution;
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
    private static final String TENANT_SOURCE_MESSAGE = "message";
    private static final TenantBindingResolution FROM_MESSAGE = new TenantBindingResolution.FromMessage("sandbox");

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
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "Baja voluntaria", ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.empty());
        when(inbox.markProcessed(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("Baja voluntaria"), FROM_MESSAGE))
                .verifyComplete();

        verify(inbox).markProcessed(MESSAGE_ID);
        verifyNoInteractions(auditService);
    }

    // ---------------------------------------------------------------- AC-03/AC-04 reason presence

    @Test
    void handleRevocationInstruction_reasonAbsent_stillRevokesWithNullReason() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.empty());
        when(inbox.markProcessed(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction(null), FROM_MESSAGE))
                .verifyComplete();

        verify(revocationWorkflow).revokeSystem(PROCESS_ID, ISSUANCE_ID, null, ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE);
    }

    // ---------------------------------------------------------------- AC-05 idempotency

    @Test
    void handleRevocationInstruction_alreadyProcessed_isNoopWithoutTouchingDomain() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(ALREADY_PROCESSED));

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .verifyComplete();

        verifyNoInteractions(publicBaseUrlResolver, revocationWorkflow, auditService);
        verify(inbox, never()).markProcessed(any());
        verify(inbox, never()).markSkipped(any());
    }

    // ---------------------------------------------------------------- EC-03 in-flight overlap

    @Test
    void handleRevocationInstruction_inProgress_propagatesRetryableError() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(IN_PROGRESS));

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .expectError(RevocationInstructionInProgressException.class)
                .verify();

        verifyNoInteractions(publicBaseUrlResolver, revocationWorkflow, auditService);
    }

    // ---------------------------------------------------------------- AC-06 no-op: not revocable

    @Test
    void handleRevocationInstruction_invalidStatus_isSkippedWithAuditAndAck() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.error(new InvalidStatusException("Invalid status: REVOKED")));
        when(inbox.markSkipped(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
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
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.error(new InvalidCredentialStatusTransitionException(
                        CredentialStatusEnum.REVOKED, CredentialStatusEnum.REVOKED)));
        when(inbox.markSkipped(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .verifyComplete();

        verify(inbox).markSkipped(MESSAGE_ID);
    }

    // ---------------------------------------------------------------- fail-closed propagation (AD-2, ES-01/02/04)

    @Test
    void handleRevocationInstruction_baseUrlNotResolvable_releasesClaimAndPropagatesError() {
        RuntimeException fatal = new RuntimeException("fail-closed: base URL not resolvable");
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.error(fatal));
        when(inbox.release(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .expectErrorMatches(e -> e == fatal)
                .verify();

        verify(inbox).release(MESSAGE_ID);
        verify(inbox, never()).markSkipped(any());
        verify(inbox, never()).markProcessed(any());
    }

    // ---------------------------------------------------------------- AC-09: release on retryable failure

    @Test
    void handleRevocationInstruction_transientFailure_releasesClaimSoNextAttemptCanReclaim() {
        RuntimeException transientError = new RuntimeException("QTSP transiently unavailable");
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.error(transientError));
        when(inbox.release(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .expectErrorMatches(e -> e == transientError)
                .verify();

        verify(inbox).release(MESSAGE_ID);
    }

    @Test
    void handleRevocationInstruction_releaseItselfFails_stillPropagatesOriginalError() {
        RuntimeException original = new RuntimeException("QTSP transiently unavailable");
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.error(original));
        when(inbox.release(MESSAGE_ID)).thenReturn(Mono.error(new RuntimeException("db down")));

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .expectErrorMatches(e -> e == original)
                .verify();
    }

    // ---------------------------------------------------------------- AC-02 audit resilience

    @Test
    void handleRevocationInstruction_auditSkippedThrows_stillMarksSkipped() {
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, TENANT_SOURCE_MESSAGE))
                .thenReturn(Mono.error(new InvalidStatusException("Invalid status: REVOKED")));
        doThrow(new RuntimeException("audit sink down"))
                .when(auditService).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyMap());
        when(inbox.markSkipped(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), FROM_MESSAGE))
                .verifyComplete();

        verify(inbox).markSkipped(MESSAGE_ID);
    }

    // ---------------------------------------------------------------- AC-11: FromDeployment tenantSource

    @Test
    void handleRevocationInstruction_fromDeployment_passesTenantSourceDeploymentToRevokeSystem() {
        TenantBindingResolution.FromDeployment fromDeployment = new TenantBindingResolution.FromDeployment("prh");
        when(inbox.claim(MESSAGE_ID, ISSUANCE_ID)).thenReturn(Mono.just(CLAIMED));
        when(publicBaseUrlResolver.resolve(ISSUANCE_ID)).thenReturn(Mono.just(BASE_URL));
        when(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, "deployment"))
                .thenReturn(Mono.empty());
        when(inbox.markProcessed(MESSAGE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), fromDeployment))
                .verifyComplete();

        verify(revocationWorkflow).revokeSystem(PROCESS_ID, ISSUANCE_ID, "reason", ACTOR, BASE_URL, "deployment");
        verify(inbox).markProcessed(MESSAGE_ID);
    }

    // ---------------------------------------------------------------- AC-12: Mismatch rejection

    @Test
    void handleRevocationInstruction_mismatch_rejectsBeforeClaimingWithAuditTrail() {
        TenantBindingResolution.Mismatch mismatch = new TenantBindingResolution.Mismatch("cgcom", "prh");

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), mismatch))
                .expectError(TenantBindingMismatchException.class)
                .verify();

        verifyNoInteractions(inbox, publicBaseUrlResolver, revocationWorkflow);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq("credential.revoke.failed"), eq(ACTOR),
                eq("tenant_binding_mismatch"), details.capture());
        assertThat(details.getValue())
                .containsEntry("errorType", "tenant_binding_mismatch")
                .containsEntry("declaredTenant", "cgcom");
    }

    @Test
    void handleRevocationInstruction_mismatch_sanitizesDeclaredTenantBeforeAuditDetail() {
        // F1 (EUD-225 /verify): a raw newline in the declared tenant must never reach an
        // audit detail unsanitized -- it could forge a second, fake AUDIT log line
        // (e.g. "cgcom\nAUDIT event=credential.revoked outcome=success ...") that a
        // downstream parser could mistake for a real revocation record.
        String forgedTenant = "cgcom\nAUDIT event=credential.revoked outcome=success resourceId=forged";
        TenantBindingResolution.Mismatch mismatch = new TenantBindingResolution.Mismatch(forgedTenant, "prh");

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), mismatch))
                .expectError(TenantBindingMismatchException.class)
                .verify();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq("credential.revoke.failed"), eq(ACTOR),
                eq("tenant_binding_mismatch"), details.capture());
        String sanitizedDeclaredTenant = (String) details.getValue().get("declaredTenant");
        assertThat(sanitizedDeclaredTenant)
                .doesNotContain("\n")
                .isEqualTo("cgcomAUDIT event=credential.revoked outcome=success resourceId=forged");
    }

    @Test
    void handleRevocationInstruction_mismatchAuditThrows_stillPropagatesMismatchError() {
        TenantBindingResolution.Mismatch mismatch = new TenantBindingResolution.Mismatch("cgcom", "prh");
        doThrow(new RuntimeException("audit sink down"))
                .when(auditService).auditFailure(anyString(), anyString(), anyString(), anyMap());

        StepVerifier.create(workflow.handleRevocationInstruction(PROCESS_ID, instruction("reason"), mismatch))
                .expectError(TenantBindingMismatchException.class)
                .verify();

        verifyNoInteractions(inbox);
    }
}
