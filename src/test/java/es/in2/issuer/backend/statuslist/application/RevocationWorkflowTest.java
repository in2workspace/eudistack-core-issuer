package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

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
    private StatusListPdpService statusListPdpService;

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

    private Issuance mockProcedure;

    @BeforeEach
    void setUp() {
        mockProcedure = new Issuance();
        mockProcedure.setCredentialType("learcredential.employee.w3c.4");
        mockProcedure.setEmail("to@example.com");
        mockProcedure.setOrganizationIdentifier("VATES-A15456585");
    }

    @Test
    void revoke_ShouldSucceed() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());
        when(statusListProvider.revoke(ISSUANCE_ID, CLEAN_TOKEN)).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID))
                .verifyComplete();

        verify(statusListProvider).revoke(ISSUANCE_ID, CLEAN_TOKEN);
    }

    @Test
    void revoke_WithNullProcessId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(null, BEARER_TOKEN, ISSUANCE_ID)
        );
    }

    @Test
    void revoke_WithNullBearerToken_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, null, ISSUANCE_ID)
        );
    }

    @Test
    void revoke_WithNullProcedureId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, null)
        );
    }

    @Test
    void revoke_WithValidationFailure_ShouldPropagateError() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void revokeSystem_ShouldSucceed() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure)).thenReturn(Mono.empty());
        when(statusListProvider.revoke(ISSUANCE_ID, CLEAN_TOKEN)).thenReturn(Mono.empty());
        when(issuanceService.updateIssuanceStatusToRevoked(mockProcedure)).thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID))
                .verifyComplete();

        verify(statusListPdpService).validateRevokeCredentialSystem(PROCESS_ID, mockProcedure);
        verify(statusListProvider).revoke(ISSUANCE_ID, CLEAN_TOKEN);
    }

    @Test
    void revokeSystem_WithValidationFailure_ShouldPropagateError() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure))
                .thenReturn(Mono.error(new RuntimeException("System validation failed")));

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, ISSUANCE_ID))
                .expectError(RuntimeException.class)
                .verify();
    }
}
