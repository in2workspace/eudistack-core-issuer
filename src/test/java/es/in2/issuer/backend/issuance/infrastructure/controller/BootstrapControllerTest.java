package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.BootstrapRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    private static BootstrapRequest buildRequest() {
        return BootstrapRequest.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .payload(JsonNodeFactory.instance.objectNode())
                .email("seed@example.com")
                .delivery("immediate")
                .build();
    }

    @Test
    void shouldReturnCreatedWhenValidTokenAndTenantInContext() {
        String token = "valid-bootstrap-token";
        String credentialOfferUri = "openid-credential-offer://example.com/offer";
        BootstrapRequest request = buildRequest();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(anyString(), any(IssuanceRequest.class)))
                .thenReturn(Mono.just(IssuanceResponse.builder().credentialOfferUri(credentialOfferUri).build()));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .assertNext(response -> {
                    assertEquals(HttpStatus.CREATED, response.getStatusCode());
                    assertEquals(credentialOfferUri, response.getHeaders().getLocation().toString());
                })
                .verifyComplete();

        ArgumentCaptor<IssuanceRequest> captor = ArgumentCaptor.forClass(IssuanceRequest.class);
        verify(bootstrapTokenService).consumeIfValid(token);
        verify(issuanceWorkflow).issueCredentialWithoutAuthorization(anyString(), captor.capture());
        IssuanceRequest forwarded = captor.getValue();
        assertEquals("learcredential.employee.w3c.4", forwarded.credentialConfigurationId());
        assertEquals("seed@example.com", forwarded.email());
    }

    @Test
    void shouldReturnBadRequestWhenTenantContextIsMissing() {
        // TenantDomainWebFilter normally rejects missing X-Tenant-Id before reaching
        // the controller, but the controller must also defend against it in case the
        // filter is bypassed or the context is not propagated correctly.
        String token = "valid-bootstrap-token";
        BootstrapRequest request = buildRequest();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.BAD_REQUEST
                                && rse.getReason() != null
                                && rse.getReason().contains("INVALID_TENANT"))
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any());
    }

    @Test
    void shouldReturnUnauthorizedWhenInvalidToken() {
        String token = "invalid-token";
        BootstrapRequest request = buildRequest();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any());
    }

    @Test
    void shouldReturnUnauthorizedWhenTokenAlreadyConsumed() {
        String token = "consumed-token";
        BootstrapRequest request = buildRequest();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();
    }
}
