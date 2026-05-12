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

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(urlResolver.publicIssuerBaseUrl(exchange)).thenReturn(PUBLIC_BASE_URL);
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(
                anyString(),
                any(IssuanceRequest.class),
                eq(token),
                eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .build()));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getHeaders().getLocation()).hasToString(credentialOfferUri);
                })
                .verifyComplete();

        ArgumentCaptor<String> processIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<IssuanceRequest> issuanceRequestCaptor = ArgumentCaptor.forClass(IssuanceRequest.class);

        verify(bootstrapTokenService).consumeIfValid(token);
        verify(urlResolver).publicIssuerBaseUrl(exchange);
        verify(auditService).auditSuccess(
                eq("bootstrap.token.used"),
                eq(null),
                eq("bootstrap"),
                processIdCaptor.capture(),
                eq(Map.of("tenant", "sandbox")));

        verify(issuanceWorkflow).issueCredentialWithoutAuthorization(
                eq(processIdCaptor.getValue()),
                issuanceRequestCaptor.capture(),
                eq(token),
                eq(PUBLIC_BASE_URL));

        IssuanceRequest forwarded = issuanceRequestCaptor.getValue();

        assertThat(processIdCaptor.getValue()).isNotBlank();
        assertThat(forwarded.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
        assertThat(forwarded.email()).isEqualTo("seed@example.com");
    }

    @Test
    void shouldReturnAcceptedWhenValidTokenAndNoCredentialOfferUri() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = buildRequest();
        ServerWebExchange exchange = newExchange();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(urlResolver.publicIssuerBaseUrl(exchange)).thenReturn(PUBLIC_BASE_URL);
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(
                anyString(),
                any(IssuanceRequest.class),
                eq(token),
                eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(null)
                        .build()));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange)
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .assertNext(response ->
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED))
                .verifyComplete();

        verify(bootstrapTokenService).consumeIfValid(token);
        verify(urlResolver).publicIssuerBaseUrl(exchange);
        verify(auditService).auditSuccess(
                eq("bootstrap.token.used"),
                eq(null),
                eq("bootstrap"),
                anyString(),
                eq(Map.of("tenant", "sandbox")));
    }

    @Test
    void shouldReturnBadRequestWhenTenantContextIsMissing() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = buildRequest();
        ServerWebExchange exchange = newExchange();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(urlResolver.publicIssuerBaseUrl(exchange)).thenReturn(PUBLIC_BASE_URL);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request, exchange))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException responseStatusException
                                && responseStatusException.getStatusCode() == HttpStatus.BAD_REQUEST
                                && responseStatusException.getReason() != null
                                && responseStatusException.getReason().contains("INVALID_TENANT"))
                .verify();

        verify(bootstrapTokenService).consumeIfValid(token);
        verify(urlResolver).publicIssuerBaseUrl(exchange);
        verify(auditService, never()).auditSuccess(anyString(), any(), anyString(), anyString(), anyMap());
        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(
                anyString(),
                any(IssuanceRequest.class),
                anyString(),
                anyString());
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
                        throwable instanceof ResponseStatusException responseStatusException
                                && responseStatusException.getStatusCode() == HttpStatus.UNAUTHORIZED
                                && responseStatusException.getReason() != null
                                && responseStatusException.getReason().contains("Invalid or already consumed bootstrap token"))
                .verify();

        verify(bootstrapTokenService).consumeIfValid(token);
        verify(urlResolver, never()).publicIssuerBaseUrl(any(ServerWebExchange.class));
        verify(auditService, never()).auditSuccess(anyString(), any(), anyString(), anyString(), anyMap());
        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(
                anyString(),
                any(IssuanceRequest.class),
                anyString(),
                anyString());
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
                        throwable instanceof ResponseStatusException responseStatusException
                                && responseStatusException.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();

        verify(bootstrapTokenService).consumeIfValid(token);
        verify(urlResolver, never()).publicIssuerBaseUrl(any(ServerWebExchange.class));
        verify(auditService, never()).auditSuccess(anyString(), any(), anyString(), anyString(), anyMap());
        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(
                anyString(),
                any(IssuanceRequest.class),
                anyString(),
                anyString());
    }
}