package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BootstrapControllerTest {

    @Mock
    private BootstrapTokenService bootstrapTokenService;

    @Mock
    private IssuanceWorkflow issuanceWorkflow;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private BootstrapController bootstrapController;

    @Test
    void shouldReturnCreatedWhenValidToken() {
        String token = "valid-bootstrap-token";
        String credentialOfferUri = "openid-credential-offer://example.com/offer";
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .delivery("immediate")
                .build();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(anyString(), any(PreSubmittedCredentialDataRequest.class)))
                .thenReturn(Mono.just(IssuanceResponse.builder().credentialOfferUri(credentialOfferUri).build()));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .assertNext(response -> {
                    assertEquals(HttpStatus.CREATED, response.getStatusCode());
                    assertEquals(credentialOfferUri, response.getHeaders().getLocation().toString());
                })
                .verifyComplete();

        verify(bootstrapTokenService).consumeIfValid(token);
        verify(issuanceWorkflow).issueCredentialWithoutAuthorization(anyString(), eq(request));
    }

    @Test
    void shouldReturnUnauthorizedWhenInvalidToken() {
        String token = "invalid-token";
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .build();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any());
    }

    @Test
    void shouldReturnUnauthorizedWhenTokenAlreadyConsumed() {
        String token = "consumed-token";
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .build();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();
    }
}
