package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialServiceImplTest {

    private final String processId = "process-id-123";
    private final String preAuthCode = "pre-auth-code-456";
    private final String transactionId = "transaction-id-789";
    private final String notificationId = "notification-id-910";
    private final Long interval = 3600L;
    private final String deferredResponseId = "deferred-response-id-456";
    private final String procedureId = "procedure-id-321";
    private final String vcValue = "vc-value-123";
    private final String testEmail = "test.user@example.com";

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @InjectMocks
    private VerifiableCredentialServiceImpl verifiableCredentialServiceImpl;

    @Test
    void bindAccessTokenByPreAuthorizedCode_Success() {
        // Arrange: Mock the service to return a Mono.empty()
        String expectedJti = "expected-jti-value";
        when(deferredCredentialMetadataService.updateAuthServerNonceByAuthServerNonce(expectedJti, preAuthCode))
                .thenReturn(Mono.empty());

        // Act: Call the method
        String validAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJleHBlY3RlZC1qdGktdmFsdWUifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        Mono<Void> result = verifiableCredentialServiceImpl.bindAccessTokenByPreAuthorizedCode(processId, validAccessToken, preAuthCode);

        // Assert: Verify the interactions and result
        StepVerifier.create(result)
                .verifyComplete();

        verify(deferredCredentialMetadataService, times(1))
                .updateAuthServerNonceByAuthServerNonce(expectedJti, preAuthCode);
    }

    @Test
    void bindAccessTokenByPreAuthorizedCode_InvalidToken_ThrowsException() {
        // Arrange: Use an invalid JWT token
        String invalidAccessToken = "invalid-token";

        // Act and Assert
        JWTParsingException exception = assertThrows(JWTParsingException.class, () ->
                verifiableCredentialServiceImpl.bindAccessTokenByPreAuthorizedCode(processId, invalidAccessToken, preAuthCode).block());
        assertEquals("Failed to parse access token JWT", exception.getMessage());

        // Verify that no interaction with deferredCredentialMetadataService happens
        verify(deferredCredentialMetadataService, times(0))
                .updateAuthServerNonceByAuthServerNonce(anyString(), anyString());
    }

    @Test
    void buildCredentialResponse_whenBindCryptographicSubjectFails_emitsFailedToBindMessage() {
        String subjectDid = "did:example:123";
        String authServerNonce = "nonce";
        String email = testEmail;
        String procedureIdLocal = "proc-bind-fail";

        String credType = "LEARCredentialEmployee";
        String decoded = "decoded";

        when(credentialProcedureService.getCredentialTypeByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(credType));
        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(decoded));

        when(credentialFactory.bindCryptographicCredentialSubjectId(processId, credType, decoded, subjectDid))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(
                        verifiableCredentialServiceImpl.buildCredentialResponse(
                                processId, subjectDid, authServerNonce, email, procedureIdLocal
                        )
                )
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(RuntimeException.class, ex);
                    assertEquals("Failed to bind cryptographic credential subject", ex.getMessage());
                    Assertions.assertNotNull(ex.getCause());
                })
                .verify();

        verify(credentialProcedureService, never())
                .updateDecodedCredentialByProcedureId(anyString(), anyString());
    }


    @Test
    void buildCredentialResponse_whenUpdateDeferredEmpty_emitsTransactionIdNotFound() {
        String subjectDid = "did:example:123";
        String authServerNonce = "nonce";
        String email = testEmail;
        String procedureIdLocal = "proc-update-deferred-empty";

        String credType = "LEARCredentialEmployee";
        String decoded = "decoded";
        String bound = "bound";

        when(credentialProcedureService.getCredentialTypeByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(credType));
        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(decoded));
        when(credentialProcedureService.getNotificationIdByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(notificationId));

        when(credentialFactory.bindCryptographicCredentialSubjectId(processId, credType, decoded, subjectDid))
                .thenReturn(Mono.just(bound));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureIdLocal, bound))
                .thenReturn(Mono.empty());

        when(deferredCredentialMetadataService.updateDeferredCredentialMetadataByAuthServerNonce(authServerNonce))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        verifiableCredentialServiceImpl.buildCredentialResponse(
                                processId, subjectDid, authServerNonce, email, procedureIdLocal
                        )
                )
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(RuntimeException.class, ex);
                    assertEquals("TransactionId not found after updating deferred metadata", ex.getMessage());
                })
                .verify();
    }

    @Test
    void buildCredentialResponse_whenFormatEmpty_emitsFormatNotFound() {
        String subjectDid = "did:example:123";
        String authServerNonce = "nonce";
        String email = testEmail;
        String procedureIdLocal = "proc-format-empty";
        String txId = "tx-2";

        String credType = "LEARCredentialEmployee";
        String decoded = "decoded";
        String bound = "bound";

        when(credentialProcedureService.getCredentialTypeByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(credType));
        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(decoded));

        when(credentialFactory.bindCryptographicCredentialSubjectId(processId, credType, decoded, subjectDid))
                .thenReturn(Mono.just(bound));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureIdLocal, bound))
                .thenReturn(Mono.empty());

        when(deferredCredentialMetadataService.updateDeferredCredentialMetadataByAuthServerNonce(authServerNonce))
                .thenReturn(Mono.just(txId));

        when(deferredCredentialMetadataService.getFormatByProcedureId(procedureIdLocal))
                .thenReturn(Mono.empty());

        when(credentialProcedureService.getNotificationIdByProcedureId(procedureIdLocal))
                .thenReturn(Mono.just(notificationId));

        StepVerifier.create(
                        verifiableCredentialServiceImpl.buildCredentialResponse(
                                processId, subjectDid, authServerNonce, email, procedureIdLocal
                        )
                )
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(RuntimeException.class, ex);
                    assertEquals(
                            "Credential format not found for procedureId: " + procedureIdLocal,
                            ex.getMessage()
                    );
                })
                .verify();
    }

}

