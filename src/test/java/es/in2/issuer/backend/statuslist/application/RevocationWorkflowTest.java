package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.CallerResolver;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.support.TestAuthorizationDecisions;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RevocationWorkflowTest {

    @Mock
    private StatusListProvider statusListProvider;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private CallerResolver callerResolver;

    @Mock
    private PowerAuthorizationService powerAuthorizationService;

    private static final Caller CALLER = new Caller("VATES-A15456585", java.util.List.of(), "sandbox", null, "sub", "jti");

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private EmailService emailService;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private RevocationWorkflow revocationWorkflow;

    private static final String PROCESS_ID = "process-123";
    private static final String BEARER_TOKEN = "Bearer token123";
    private static final String CLEAN_TOKEN = "token123";
    private static final String ISSUANCE_ID = "procedure-456";
    private static final String SYSTEM_ACTOR = "system:oid4vci-notification";

    private Issuance mockProcedure;

    @BeforeEach
    void setUp() {
        mockProcedure = new Issuance();
        mockProcedure.setCredentialType("learcredential.employee.w3c.4");
        mockProcedure.setEmail("to@example.com");
        mockProcedure.setOrganizationIdentifier("VATES-A15456585");
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
    }

    private void permitRevocation() {
        when(callerResolver.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(eq(PowerAuthorizationService.REVOKE), eq(CALLER), eq("VATES-A15456585"), any()))
                .thenReturn(Mono.just(TestAuthorizationDecisions.query("VATES-A15456585", UserRole.LEAR, false)));
    }

    @Test
    void revoke_ShouldSucceed() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
        when(statusListProvider.revoke(ISSUANCE_ID, CLEAN_TOKEN, "https://issuer.example.com")).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .verifyComplete();

        verify(statusListProvider).revoke(ISSUANCE_ID, CLEAN_TOKEN, "https://issuer.example.com");
    }

    @Test
    void revoke_WithNullProcessId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(null, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com")
        );
    }

    @Test
    void revoke_WithNullBearerToken_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, null, ISSUANCE_ID, null, "https://issuer.example.com")
        );
    }

    @Test
    void revoke_WithNullProcedureId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, null, null, "https://issuer.example.com")
        );
    }

    @Test
    void revoke_WithNonExistentIssuance_ShouldThrowIssuanceNotFoundException() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(IssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(powerAuthorizationService, statusListProvider);
    }

    @Test
    void revoke_WithValidationFailure_ShouldPropagateError() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(callerResolver.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(any(), any(), any(), any())).thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void revokeSystem_ShouldSucceed() {
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListProvider.revoke(ISSUANCE_ID, null, "https://issuer.example.com")).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, SYSTEM_ACTOR, "https://issuer.example.com"))
                .verifyComplete();

        verifyNoInteractions(powerAuthorizationService);
        verify(statusListProvider).revoke(ISSUANCE_ID, null, "https://issuer.example.com");
        verifyNoInteractions(accessTokenService);
    }

    @Test
    void revokeSystem_WithNullActor_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, null, "https://issuer.example.com")
        );
    }

    @Test
    void revokeSystem_WithNullProcessId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revokeSystem(null, ISSUANCE_ID, null, SYSTEM_ACTOR, "https://issuer.example.com")
        );
    }

    @Test
    void revokeSystem_WithNullIssuanceId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revokeSystem(PROCESS_ID, null, null, SYSTEM_ACTOR, "https://issuer.example.com")
        );
    }

    @Test
    void revokeSystem_WithValidationFailure_ShouldPropagateError() {
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        mockProcedure.setCredentialStatus(CredentialStatusEnum.REVOKED);

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, SYSTEM_ACTOR, "https://issuer.example.com"))
                .expectError(InvalidStatusException.class)
                .verify();
    }

    @SuppressWarnings("unchecked")
    @Test
    void revokeSystem_usesExplicitActor_neverUnknown() {
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListProvider.revoke(ISSUANCE_ID, null, "https://issuer.example.com")).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, SYSTEM_ACTOR, "https://issuer.example.com"))
                .verifyComplete();

        verify(auditService).auditAttempted(
                eq("credential.revoke.attempted"), eq(SYSTEM_ACTOR), eq("credential"), eq(ISSUANCE_ID), any());
        verify(auditService).auditSuccess(
                eq("credential.revoked"), eq(SYSTEM_ACTOR), eq("credential"), eq(ISSUANCE_ID), any());
    }

    // ---------------------------------------------------------------- AC-01, AC-03, AC-07 (audit content)

    private void mockHappyPath() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
        when(statusListProvider.revoke(ISSUANCE_ID, CLEAN_TOKEN, "https://issuer.example.com")).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
    }

    @SuppressWarnings("unchecked")
    @Test
    void revoke_success_emitsAttemptedThenEnrichedSuccessAudit() {
        mockHappyPath();
        var auth = new UsernamePasswordAuthenticationToken("alice@example.com", "n/a", List.of());

        StepVerifier.create(
                revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, "Baja del empleado", "https://issuer.example.com")
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
        ).verifyComplete();

        ArgumentCaptor<Map<String, Object>> successDetails = ArgumentCaptor.forClass(Map.class);
        InOrder inOrder = inOrder(auditService);
        inOrder.verify(auditService).auditAttempted(
                eq("credential.revoke.attempted"), eq("alice@example.com"), eq("credential"), eq(ISSUANCE_ID), any());
        inOrder.verify(auditService).auditSuccess(
                eq("credential.revoked"), eq("alice@example.com"), eq("credential"), eq(ISSUANCE_ID), successDetails.capture());

        assertThat(successDetails.getValue())
                .containsEntry("organizationId", "VATES-A15456585")
                .containsEntry("reason", "Baja del empleado")
                .containsEntry("outcome", "success")
                .doesNotContainKeys("email", "subject", "token");
    }

    @SuppressWarnings("unchecked")
    @Test
    void revoke_withoutReason_stillSucceeds_reasonMarkedNotProvided() {
        mockHappyPath();

        StepVerifier.create(
                revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com")
        ).verifyComplete();

        ArgumentCaptor<Map<String, Object>> successDetails = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditSuccess(eq("credential.revoked"), any(), eq("credential"), eq(ISSUANCE_ID), successDetails.capture());
        assertThat(successDetails.getValue()).containsEntry("reason", "not-provided");
    }

    // ---------------------------------------------------------------- EC-02 (unknown actor)

    @Test
    void revoke_noSecurityContext_usesUnknownActorAndStillSucceeds() {
        mockHappyPath();

        StepVerifier.create(
                revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com")
        ).verifyComplete();

        verify(auditService).auditAttempted(
                eq("credential.revoke.attempted"), eq("unknown"), eq("credential"), eq(ISSUANCE_ID), any());
        verify(auditService).auditSuccess(
                eq("credential.revoked"), eq("unknown"), eq("credential"), eq(ISSUANCE_ID), any());
    }

    // ---------------------------------------------------------------- AC-02 (failure audit)

    @SuppressWarnings("unchecked")
    @Test
    void revoke_invalidStatus_emitsFailedAuditWithCategorizedErrorType() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
        mockProcedure.setCredentialStatus(CredentialStatusEnum.REVOKED);

        StepVerifier.create(
                revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com")
        ).expectError(InvalidStatusException.class).verify();

        ArgumentCaptor<Map<String, Object>> failureDetails = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq("credential.revoke.failed"), any(), eq("invalid_status"), failureDetails.capture());
        assertThat(failureDetails.getValue())
                .containsEntry("errorType", "invalid_status")
                .containsEntry("organizationId", "VATES-A15456585");
        verify(statusListProvider, never()).revoke(any(), any(), any());
    }

    // ---------------------------------------------------------------- ES-02 (unknown issuanceId)

    @Test
    void revoke_nonExistentIssuance_emitsAttemptedAndFailedAudit() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.empty());

        StepVerifier.create(
                revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com")
        ).expectError(IssuanceNotFoundException.class).verify();

        verify(auditService).auditAttempted(
                eq("credential.revoke.attempted"), any(), eq("credential"), eq(ISSUANCE_ID), any());
        verify(auditService).auditFailure(eq("credential.revoke.failed"), any(), eq("issuance_not_found"), any());
    }

    // ---------------------------------------------------------------- ES-04 (audit failure doesn't revert)

    @Test
    void revoke_auditSuccessThrows_doesNotFailRevocation() {
        mockHappyPath();
        doThrow(new RuntimeException("audit sink down"))
                .when(auditService).auditSuccess(eq("credential.revoked"), any(), any(), any(), any());

        StepVerifier.create(
                revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com")
        ).verifyComplete();

        verify(issuanceService).updateIssuanceStatusToRevoked(mockProcedure);
    }

    /** EUD-272 AC: a resource of another organization reads as not found and leaves its reason in the trace. */
    @SuppressWarnings("unchecked")
    @Test
    void revoke_outOfScope_failsAsIssuanceNotFound_andAuditsIt() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(callerResolver.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(any(), any(), any(), any()))
                .thenReturn(Mono.error(new IssuanceNotFoundException("No issuance found for issuanceId: " + ISSUANCE_ID)));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(IssuanceNotFoundException.class)
                .verify();

        verify(auditService).auditFailure(eq("credential.revoke.failed"), any(), eq("issuance_not_found"), any(Map.class));
        verifyNoInteractions(statusListProvider);
    }

    @Test
    void revoke_deniedByPowers_neverChecksStatusNorRevokes() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.REVOKED);
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(callerResolver.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(any(), any(), any(), any()))
                .thenReturn(Mono.error(new LearIssuancePolicyException(
                        LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "no power")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(LearIssuancePolicyException.class)
                .verify();

        verifyNoInteractions(statusListProvider);
    }
}
