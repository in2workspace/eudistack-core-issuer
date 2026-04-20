package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.BootstrapRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
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

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

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

    @Mock
    private BootstrapTokenService bootstrapTokenService;

    @Mock
    private IssuanceWorkflow issuanceWorkflow;

    @Mock
    private AuditService auditService;

    @Mock
    private TenantRegistryService tenantRegistryService;

    @InjectMocks
    private BootstrapController bootstrapController;

    private static BootstrapRequest requestWithTenant(String tenant) {
        return BootstrapRequest.builder()
                .tenant(tenant)
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .payload(JsonNodeFactory.instance.objectNode())
                .email("seed@example.com")
                .delivery("immediate")
                .build();
    }

    @Test
    void shouldReturnCreatedWhenValidTokenAndValidTenant() {
        String token = "valid-bootstrap-token";
        String credentialOfferUri = "openid-credential-offer://example.com/offer";
        BootstrapRequest request = requestWithTenant("sandbox");

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("sandbox")));
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(anyString(), any(IssuanceRequest.class)))
                .thenReturn(Mono.just(IssuanceResponse.builder().credentialOfferUri(credentialOfferUri).build()));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
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
    void shouldPropagateTenantInReactorContext() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = requestWithTenant("sandbox");
        AtomicReference<String> seenTenant = new AtomicReference<>();

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("sandbox")));
        when(issuanceWorkflow.issueCredentialWithoutAuthorization(anyString(), any(IssuanceRequest.class)))
                .thenReturn(Mono.deferContextual(ctx -> {
                    seenTenant.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
                    return Mono.just(IssuanceResponse.builder()
                            .credentialOfferUri("openid-credential-offer://example.com/offer")
                            .build());
                }));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectNextCount(1)
                .verifyComplete();

        assertEquals("sandbox", seenTenant.get());
    }

    @Test
    void shouldReturnUnauthorizedWhenInvalidToken() {
        String token = "invalid-token";
        BootstrapRequest request = requestWithTenant("sandbox");

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any());
        verify(tenantRegistryService, never()).getActiveTenantSchemas();
    }

    @Test
    void shouldReturnUnauthorizedWhenTokenAlreadyConsumed() {
        String token = "consumed-token";
        BootstrapRequest request = requestWithTenant("sandbox");

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(false);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verify();
    }

    @Test
    void shouldReturnBadRequestWhenTenantIsBlank() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = requestWithTenant("   ");

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        lenient().when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("sandbox")));

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
    void shouldReturnBadRequestWhenTenantIsMalformed() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = requestWithTenant("bad tenant!");

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.BAD_REQUEST
                                && rse.getReason() != null
                                && rse.getReason().contains("INVALID_TENANT"))
                .verify();

        verify(tenantRegistryService, never()).getActiveTenantSchemas();
        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any());
    }

    @Test
    void shouldReturnNotFoundWhenTenantNotRegistered() {
        String token = "valid-bootstrap-token";
        BootstrapRequest request = requestWithTenant("unknown");

        when(bootstrapTokenService.consumeIfValid(token)).thenReturn(true);
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("sandbox")));

        StepVerifier.create(bootstrapController.bootstrapIssueCredential(token, request))
                .expectErrorMatches(throwable ->
                        throwable instanceof ResponseStatusException rse
                                && rse.getStatusCode() == HttpStatus.NOT_FOUND
                                && rse.getReason() != null
                                && rse.getReason().contains("TENANT_NOT_FOUND"))
                .verify();

        verify(issuanceWorkflow, never()).issueCredentialWithoutAuthorization(anyString(), any());
    }
}
