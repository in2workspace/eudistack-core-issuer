package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.BootstrapRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BootstrapControllerTest {

    private static final String PUBLIC_BASE_URL = "https://test.example/issuer";

    @Mock
    private BootstrapTokenService bootstrapTokenService;

    @Mock
    private IssuanceWorkflow issuanceWorkflow;

    @Mock
    private AuditService auditService;

    @Mock
    private UrlResolver urlResolver;

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

    private static ServerWebExchange newExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.post("/bootstrap"));
    }

    @Test
    void shouldReturnCreatedWhenValidTokenAndTenantInContext() {
        String token = "valid-bootstrap-token";
        String credentialOfferUri = "openid-credential-offer://example.com/offer";
        BootstrapRequest request = buildRequest();
        ServerWebExchange exchange = newExchange();

        lenient().when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(anyString(), any(IssuanceRequest.class), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder().credentialOfferUri(credentialOfferUri).build()));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .assertNext(response -> {
                    assertEquals(HttpStatus.CREATED, response.getStatusCode());
                    assertEquals(credentialOfferUri, response.getHeaders().getLocation().toString());
                })
                .verifyComplete();

        ArgumentCaptor<IssuanceRequest> captor = ArgumentCaptor.forClass(IssuanceRequest.class);
        verify(bootstrapTokenService).consumeIfValid(token);
        verify(issuanceWorkflow).issueCredentialWithoutAuthorization(anyString(), captor.capture(), eq(PUBLIC_BASE_URL));
        IssuanceRequest forwarded = captor.getValue();
        assertEquals("learcredential.employee.w3c.4", forwarded.credentialConfigurationId());
        assertEquals("seed@example.com", forwarded.email());
    }

    @Test
    void shouldReturnBadRequestWhenTenantContextIsMissing() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = buildRequest();
        ServerWebExchange exchange = newExchange();

        lenient().when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.BAD_REQUEST
                                && rse.getReason() != null
                                && rse.getReason().contains("INVALID_TENANT"))
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any(), anyString());
    }

    @Test
    void shouldReturnUnauthorizedWhenInvalidToken() {
        String token = "invalid-token";
        BootstrapRequest request = buildRequest();
        ServerWebExchange exchange = newExchange();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any(), anyString());
    }

    @Test
    void shouldReturnUnauthorizedWhenTokenAlreadyConsumed() {
        String token = "consumed-token";
        BootstrapRequest request = buildRequest();
        ServerWebExchange exchange = newExchange();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();
    }
}
