package es.in2.issuer.backend.statuslist.application;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.statuslist.domain.exception.AlreadyRevokedException;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationRequestException;
import es.in2.issuer.backend.statuslist.domain.exception.NotRevocableException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.support.TestAuthorizationDecisions;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
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
    private CallerProvider callerProvider;

    @Mock
    private PowerAuthorizationService powerAuthorizationService;

    private static final Caller CALLER = new Caller("VATES-A15456585", java.util.List.of(), "sandbox", null, "jti");

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private EmailService emailService;

    @Mock
    private AuditService auditService;

    @Mock
    private JWTService jwtService;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

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
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(eq(PowerAuthorizationService.REVOKE), eq(CALLER), eq("VATES-A15456585"), any()))
                .thenReturn(Mono.just(TestAuthorizationDecisions.query("VATES-A15456585", UserRole.LEAR, false)));
    }

    /** A process stored without organization (pre EUD-272) must not read as "no resource" to the decision point. */
    @Test
    void revoke_processWithoutOrganization_isDecidedAsBelongingToNoOrganization() {
        mockProcedure.setOrganizationIdentifier(null);
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(eq(PowerAuthorizationService.REVOKE), eq(CALLER), eq(""), any()))
                .thenReturn(Mono.error(new IssuanceNotFoundException("No issuance found")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(IssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(statusListProvider);
    }

    @Test
    void revoke_ShouldSucceed() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
        when(statusListProvider.revoke(eq(ISSUANCE_ID), eq(CLEAN_TOKEN), eq("https://issuer.example.com"), any())).thenAnswer(inv -> inv.getArgument(3));
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .verifyComplete();

        verify(statusListProvider).revoke(eq(ISSUANCE_ID), eq(CLEAN_TOKEN), eq("https://issuer.example.com"), any());
    }

    /** The PATCH route does not check the shape of its id, and the JDK repeats a malformed one in its message. */
    @Test
    void revoke_malformedId_cannotForgeALogLine() {
        String forged = "x\nFAKE action=forged";
        Logger logger = (Logger) LoggerFactory.getLogger(RevocationWorkflow.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(forged)).thenThrow(new IllegalArgumentException("Invalid UUID string: " + forged));

        try {
            StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, forged, null, "https://issuer.example.com"))
                    .verifyError(IllegalArgumentException.class);
        } finally {
            logger.detachAppender(logs);
        }

        assertThat(logs.list).extracting(ILoggingEvent::getFormattedMessage)
                .isNotEmpty()
                .noneMatch(message -> message.contains("\n"));
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
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, CALLER, null, ISSUANCE_ID))
                .thenReturn(Mono.just(TestAuthorizationDecisions.query("VATES-A15456585", UserRole.LEAR, false)));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(IssuanceNotFoundException.class)
                        .hasMessage("No issuance found for the given id"))
                .verify();

        verifyNoInteractions(statusListProvider);
    }

    /** A caller who may not revoke is denied whether or not the id exists: the answer does not reveal it. */
    @Test
    void revoke_withoutThePower_nonExistentIssuance_isDeniedNotNotFound() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.empty());
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, CALLER, null, ISSUANCE_ID))
                .thenReturn(Mono.error(new LearIssuancePolicyException(LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "denied")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(LearIssuancePolicyException.class)
                .verify();

        verifyNoInteractions(statusListProvider);
    }

    @Test
    void revoke_WithValidationFailure_ShouldPropagateError() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(any(), any(), any(), any())).thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, "https://issuer.example.com"))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void revokeSystem_ShouldSucceed() {
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListProvider.revoke(eq(ISSUANCE_ID), isNull(), eq("https://issuer.example.com"), any())).thenAnswer(inv -> inv.getArgument(3));
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, ISSUANCE_ID, null, SYSTEM_ACTOR, "https://issuer.example.com"))
                .verifyComplete();

        verifyNoInteractions(powerAuthorizationService);
        verify(statusListProvider).revoke(eq(ISSUANCE_ID), isNull(), eq("https://issuer.example.com"), any());
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
        when(statusListProvider.revoke(eq(ISSUANCE_ID), isNull(), eq("https://issuer.example.com"), any())).thenAnswer(inv -> inv.getArgument(3));
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
        when(statusListProvider.revoke(eq(ISSUANCE_ID), eq(CLEAN_TOKEN), eq("https://issuer.example.com"), any())).thenAnswer(inv -> inv.getArgument(3));
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
        verify(statusListProvider, never()).revoke(any(), any(), any(), any());
    }

    // ---------------------------------------------------------------- ES-02 (unknown issuanceId)

    @Test
    void revoke_nonExistentIssuance_emitsAttemptedAndFailedAudit() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.empty());
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, CALLER, null, ISSUANCE_ID))
                .thenReturn(Mono.just(TestAuthorizationDecisions.query("VATES-A15456585", UserRole.LEAR, false)));

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

    // ---------------------------------------------------------------- EUD-271: the contract's route

    private static final String UUID_ID = "0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90";
    private static final String BASE_URL = "https://issuer.example.com";
    private static final String REASON = "Baja del empleado";

    private void mockRequester() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(accessTokenService.getOrganizationId(BEARER_TOKEN)).thenReturn(Mono.just("VATES-REQUESTER"));
    }

    private void mockContractPathUpToStatus() {
        mockRequester();
        when(issuanceService.getIssuanceById(UUID_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
    }

    private void mockMarkAndNotify() {
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any())).thenAnswer(inv -> inv.getArgument(3));
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
    }

    private Mono<Void> revokeIssuance(String reason) {
        return revocationWorkflow.revokeIssuance(PROCESS_ID, BEARER_TOKEN, UUID_ID, reason, BASE_URL);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> capturedSuccessDetails() {
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditSuccess(eq("credential.revoked"), any(), eq("credential"), eq(UUID_ID), details.capture());
        return details.getValue();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> capturedFailureDetails(String errorType) {
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq("credential.revoke.failed"), any(), eq(errorType), details.capture());
        return details.getValue();
    }

    @Test
    void revokeIssuance_valid_marksNotifiesWithoutReason_andTracesHolderInClear() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockProcedure.setSubject("Ana Holder");
        mockProcedure.setCredentialDataSet("{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"employeeId\":\"E-77\"}}}}");
        mockContractPathUpToStatus();
        mockMarkAndNotify();

        StepVerifier.create(revokeIssuance(REASON)).verifyComplete();

        // The notification has no way to carry the reason: id, type and status are all it receives.
        verify(emailService).sendCredentialStatusChangeNotification("to@example.com", "cred-123",
                "learcredential.employee.w3c.4", "REVOKED");
        assertThat(capturedSuccessDetails())
                .containsEntry("reason", REASON)
                .containsEntry("organizationId", "VATES-A15456585")
                .containsEntry("requesterOrganizationId", "VATES-REQUESTER")
                .containsEntry("holderName", "Ana Holder")
                .containsEntry("holderEmail", "to@example.com")
                .containsEntry("holderDocument", "E-77");
    }

    @Test
    void revokeIssuance_holderWithoutDocument_leavesItEmptyAndStillRevokes() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockProcedure.setCredentialDataSet("not json");
        mockContractPathUpToStatus();
        mockMarkAndNotify();

        StepVerifier.create(revokeIssuance(REASON)).verifyComplete();

        assertThat(capturedSuccessDetails()).containsEntry("holderDocument", "");
    }

    /** A system's sub is the IP its attestation declares: the DID of its mandatee is what identifies it. */
    @Test
    void revokeIssuance_systemToken_tracesTheDidOfTheMandateeAsActor_notItsSub() throws Exception {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        mockMarkAndNotify();
        SignedJWT jwt = mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet()).thenReturn(new JWTClaimsSet.Builder().subject("127.0.0.1")
                .claim("mandatee", Map.of("id", "did:key:system", "ipAddress", "127.0.0.1")).build());
        when(jwtService.parseJWT(CLEAN_TOKEN)).thenReturn(jwt);

        StepVerifier.create(revokeIssuance(REASON)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                                new UsernamePasswordAuthenticationToken("anonymous", "n/a", List.of()))))
                .verifyComplete();

        verify(auditService).auditSuccess(eq("credential.revoked"), eq("did:key:system"), eq("credential"), eq(UUID_ID), any());
    }

    /** The person of an SD-JWT attestation arrives as anonymous too, and is named by their email. */
    @Test
    void revoke_alias_sdJwtPerson_tracesTheEmailOfTheMandateeAsActor() throws Exception {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
        when(statusListProvider.revoke(eq(ISSUANCE_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any())).thenReturn(Mono.error(new RuntimeException("stop")));
        SignedJWT jwt = mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet()).thenReturn(new JWTClaimsSet.Builder().subject("other")
                .claim("mandatee", Map.of("email", "person@example.com", "id", "did:key:x")).build());
        when(jwtService.parseJWT(CLEAN_TOKEN)).thenReturn(jwt);

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, BASE_URL)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                                new UsernamePasswordAuthenticationToken("anonymous", "n/a", List.of()))))
                .expectError()
                .verify();

        verify(auditService).auditFailure(eq("credential.revoke.failed"), eq("person@example.com"), any(), any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void traceUnauthenticated_namesAnAnonymousActor_andSanitizesWhatTheClientSent() {
        revocationWorkflow.traceUnauthenticated("id\nforged=1", "motivo\r\nforged=2", "invalid_token", "203.0.113.7");

        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq("credential.revoke.failed"), eq("anonymous"), eq("invalid_token"), details.capture());
        assertThat(details.getValue())
                .containsEntry("actor", "anonymous")
                .containsEntry("reason", "motivoforged=2")
                .containsEntry("resourceId", "idforged=1")
                .containsEntry("clientAddress", "203.0.113.7")
                .containsEntry("errorType", "invalid_token");
    }

    @Test
    void traceUnauthenticated_aFailingAuditNeverPropagates() {
        org.mockito.Mockito.doThrow(new RuntimeException("audit down")).when(auditService).auditFailure(any(), any(), any(), any());

        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() ->
                revocationWorkflow.traceUnauthenticated(UUID_ID, null, "invalid_token", ""));
    }

    @Test
    void revokeIssuance_anonymousPrincipal_tracesTheTokensIdentifierAsActor() throws Exception {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        mockMarkAndNotify();
        SignedJWT jwt = mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet()).thenReturn(new JWTClaimsSet.Builder().claim("client_id", "did:key:system").build());
        when(jwtService.parseJWT(CLEAN_TOKEN)).thenReturn(jwt);

        StepVerifier.create(revokeIssuance(REASON)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                                new UsernamePasswordAuthenticationToken("anonymous", "n/a", List.of()))))
                .verifyComplete();

        verify(auditService).auditSuccess(eq("credential.revoked"), eq("did:key:system"), eq("credential"), eq(UUID_ID), any());
    }

    @Test
    void revokeIssuance_alreadyRevoked_failsWithoutRepeatingAnyEffect() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.REVOKED);
        mockContractPathUpToStatus();

        StepVerifier.create(revokeIssuance(REASON)).expectError(AlreadyRevokedException.class).verify();

        verifyNoInteractions(statusListProvider, emailService);
        assertThat(capturedFailureDetails("already_revoked")).containsEntry("reason", REASON);
    }

    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = {"VALID", "REVOKED"}, mode = EnumSource.Mode.EXCLUDE)
    void revokeIssuance_notValid_failsAsNotRevocable(CredentialStatusEnum status) {
        mockProcedure.setCredentialStatus(status);
        mockContractPathUpToStatus();

        StepVerifier.create(revokeIssuance(REASON)).expectError(NotRevocableException.class).verify();

        verifyNoInteractions(statusListProvider, emailService);
    }

    @Test
    void revokeIssuance_missingProcess_decidesThePowerFirst_thenAnswersNotFound() {
        mockRequester();
        when(issuanceService.getIssuanceById(UUID_ID)).thenReturn(Mono.empty());
        when(callerProvider.fromToken(CLEAN_TOKEN)).thenReturn(Mono.just(CALLER));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, CALLER, null, UUID_ID))
                .thenReturn(Mono.just(TestAuthorizationDecisions.query("VATES-A15456585", UserRole.LEAR, false)));

        StepVerifier.create(revokeIssuance(REASON)).expectError(IssuanceNotFoundException.class).verify();

        verify(powerAuthorizationService).authorize(PowerAuthorizationService.REVOKE, CALLER, null, UUID_ID);
        assertThat(capturedFailureDetails("issuance_not_found")).containsEntry("requesterOrganizationId", "VATES-REQUESTER");
    }

    @Test
    void revokeIssuance_invalidShape_isRejectedAndTraced_withoutLookingForTheProcess() {
        mockRequester();

        StepVerifier.create(revocationWorkflow.revokeIssuance(PROCESS_ID, BEARER_TOKEN, "not-a-uuid", null, BASE_URL))
                .expectErrorSatisfies(e -> assertThat(((InvalidRevocationRequestException) e).getViolations())
                        .extracting("field").containsExactly("id", "reason"))
                .verify();

        verifyNoInteractions(issuanceService, statusListProvider, powerAuthorizationService);
        verify(auditService).auditFailure(eq("credential.revoke.failed"), any(), eq("BAD_REQUEST"), any());
    }

    @Test
    void revokeIssuance_lostRace_failsAsAlreadyRevoked_withOneNotice() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new InvalidCredentialStatusTransitionException(
                        CredentialStatusEnum.REVOKED, CredentialStatusEnum.REVOKED)));

        StepVerifier.create(revokeIssuance(REASON)).expectError(AlreadyRevokedException.class).verify();

        verifyNoInteractions(emailService);
    }

    @Test
    void revokeIssuance_statusChangedToAnotherOne_failsAsNotRevocable() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new InvalidCredentialStatusTransitionException(
                        CredentialStatusEnum.EXPIRED, CredentialStatusEnum.REVOKED)));

        StepVerifier.create(revokeIssuance(REASON)).expectError(NotRevocableException.class).verify();
    }

    @Test
    void revokeIssuance_withoutListPosition_failsAsNotRevocable() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new StatusListIndexNotFoundException(UUID_ID)));

        StepVerifier.create(revokeIssuance(REASON)).expectError(NotRevocableException.class).verify();
    }

    @Test
    void revokeIssuance_listCannotBeMarked_failsAsUnavailable_withoutNotifying() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new RemoteSignatureException("QTSP down")));

        StepVerifier.create(revokeIssuance(REASON)).expectError(StatusListUnavailableException.class).verify();

        verifyNoInteractions(emailService);
        assertThat(capturedFailureDetails("status_list_unavailable")).isNotEmpty();
    }

    @Test
    void revokeIssuance_auditFailsAfterTheRevocation_keepsTheRevocation() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        mockMarkAndNotify();
        doThrow(new IllegalStateException("audit down")).when(auditService).auditSuccess(any(), any(), any(), any(), any());

        StepVerifier.create(revokeIssuance(REASON)).verifyComplete();

        verify(issuanceService).updateIssuanceStatusToRevoked(mockProcedure);
    }

    @Test
    void revoke_alias_keepsItsErrors_whenTheListCannotBeMarked() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        permitRevocation();
        when(statusListProvider.revoke(eq(ISSUANCE_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new RemoteSignatureException("QTSP down")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID, null, BASE_URL))
                .expectError(RemoteSignatureException.class)
                .verify();
    }

    @Test
    void revokeIssuance_listVanished_failsAsNotRevocable_notAsARetry() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException(1L)));

        StepVerifier.create(revokeIssuance(REASON)).expectError(NotRevocableException.class).verify();
    }

    @Test
    void revokeIssuance_programmingError_isNotToldToRetry() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockContractPathUpToStatus();
        when(statusListProvider.revoke(eq(UUID_ID), eq(CLEAN_TOKEN), eq(BASE_URL), any()))
                .thenReturn(Mono.error(new NullPointerException("bug")));

        StepVerifier.create(revokeIssuance(REASON)).expectError(NullPointerException.class).verify();
    }

    @Test
    void revokeIssuance_nullDocumentField_keepsLookingForARealDocument() {
        mockProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        mockProcedure.setCredentialDataSet("{\"document_number\":null,\"mandate\":{\"mandatee\":{\"employeeId\":\"E1\"}}}");
        mockContractPathUpToStatus();
        mockMarkAndNotify();

        StepVerifier.create(revokeIssuance(REASON)).verifyComplete();

        assertThat(capturedSuccessDetails()).containsEntry("holderDocument", "E1");
    }

    @Test
    void revokeIssuance_rejectedId_reachesTheAuditUnquoted() {
        mockRequester();

        StepVerifier.create(revocationWorkflow.revokeIssuance(PROCESS_ID, BEARER_TOKEN, "a=b", REASON, BASE_URL))
                .expectError(InvalidRevocationRequestException.class)
                .verify();

        assertThat(capturedFailureDetails("BAD_REQUEST")).containsEntry("resourceId", "a=b");
    }
}
