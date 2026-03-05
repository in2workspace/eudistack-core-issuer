package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
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
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private RevocationWorkflow revocationWorkflow;

    private static final String PROCESS_ID = "process-123";
    private static final String BEARER_TOKEN = "Bearer token123";
    private static final String CLEAN_TOKEN = "token123";
    private static final String PROCEDURE_ID = "procedure-456";

    private CredentialProcedure mockProcedure;

    @BeforeEach
    void setUp() {
        mockProcedure = new CredentialProcedure();
        mockProcedure.setCredentialType("LEARCredentialEmployee");
    }

    @Test
    void revoke_ShouldSucceed() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());
        when(statusListProvider.revoke(PROCEDURE_ID, CLEAN_TOKEN)).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(credentialProcedureService.getCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("to@example.com", "ACME Corp")));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), any(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID))
                .verifyComplete();

        verify(statusListProvider).revoke(PROCEDURE_ID, CLEAN_TOKEN);
    }

    @Test
    void revoke_WithNullProcessId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(null, BEARER_TOKEN, PROCEDURE_ID)
        );
    }

    @Test
    void revoke_WithNullBearerToken_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, null, PROCEDURE_ID)
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
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void revokeSystem_ShouldSucceed() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure)).thenReturn(Mono.empty());
        when(statusListProvider.revoke(PROCEDURE_ID, CLEAN_TOKEN)).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(credentialProcedureService.getCredentialId(mockProcedure)).thenReturn(Mono.just("cred-123"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("to@example.com", "ACME Corp")));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), any(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID))
                .verifyComplete();

        verify(statusListPdpService).validateRevokeCredentialSystem(PROCESS_ID, mockProcedure);
        verify(statusListProvider).revoke(PROCEDURE_ID, CLEAN_TOKEN);
    }

    @Test
    void revokeSystem_WithValidationFailure_ShouldPropagateError() {
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure))
                .thenReturn(Mono.error(new RuntimeException("System validation failed")));

        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID))
                .expectError(RuntimeException.class)
                .verify();
    }
}
