package es.in2.issuer.backend.apiclient.application.service.impl;

import es.in2.issuer.backend.apiclient.domain.exception.ApiClientAuthenticationException;
import es.in2.issuer.backend.apiclient.domain.model.ApiClient;
import es.in2.issuer.backend.apiclient.domain.model.AuthenticatedApiClient;
import es.in2.issuer.backend.apiclient.domain.model.AuthorizationStatus;
import es.in2.issuer.backend.apiclient.domain.spi.ApiClientRepository;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiClientAuthenticationServiceImplTest {

    private static final String TENANT = "acme";
    private static final String CLIENT_ID = "acme-hr";
    private static final String RAW_SECRET = "s3cr3t-value";

    @Mock
    private ApiClientRepository apiClientRepository;

    @Mock
    private AuditService auditService;

    private final PasswordEncoder secretHasher = new BCryptPasswordEncoder();

    private final PasswordEncoder passwordEncoder = spy(secretHasher);

    private ApiClientAuthenticationServiceImpl service;

    private void init() {
        service = new ApiClientAuthenticationServiceImpl(apiClientRepository, passwordEncoder, auditService);
    }

    private ApiClient clientWith(AuthorizationStatus status, boolean canTriggerIssuance) {
        return new ApiClient(CLIENT_ID, status, canTriggerIssuance, secretHasher.encode(RAW_SECRET));
    }

    @Test
    void authenticateForToken_activeClientValidSecret_returnsAuthenticatedApiClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectNextMatches(client -> client.clientId().equals(CLIENT_ID) && client.canTriggerIssuance())
                .verifyComplete();
        verify(auditService).auditSuccess(eq("intake.auth.success"), eq(CLIENT_ID), anyString(), anyString(), anyMapArg());
    }

    @Test
    void authenticateForToken_unknownClientId_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID)).thenReturn(Mono.empty());

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("client_not_found"), anyMapArg());
    }

    @Test
    void authenticateForToken_unknownClientId_comparesAgainstValidBcryptHash() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID)).thenReturn(Mono.empty());
        Mockito.clearInvocations(passwordEncoder);

        StepVerifier.create(service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET))
                .expectError(ApiClientAuthenticationException.class)
                .verify();

        ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
        verify(passwordEncoder).matches(eq(RAW_SECRET), hashCaptor.capture());
        assertThat(hashCaptor.getValue()).matches("^\\$2[aby]\\$\\d{2}\\$[./A-Za-z0-9]{53}$");
    }

    @Test
    void authenticateForToken_secretLongerThan72Bytes_deniesAsInvalidSecretNotRepositoryError() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        StepVerifier.create(service.authenticateForToken(TENANT, CLIENT_ID, "x".repeat(73)))
                .expectError(ApiClientAuthenticationException.class)
                .verify();

        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("invalid_secret"), anyMapArg());
    }

    @Test
    void authenticateForToken_unknownClientAndSecretLongerThan72Bytes_deniesAsClientNotFound() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID)).thenReturn(Mono.empty());

        StepVerifier.create(service.authenticateForToken(TENANT, CLIENT_ID, "x".repeat(73)))
                .expectError(ApiClientAuthenticationException.class)
                .verify();

        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("client_not_found"), anyMapArg());
    }

    @Test
    void authenticateForToken_wrongSecret_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, "wrong-secret");

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("invalid_secret"), anyMapArg());
    }

    @Test
    void authenticateForToken_revokedClient_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.REVOKED, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("client_not_active"), anyMapArg());
    }

    @Test
    void authenticateForToken_suspendedClient_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.SUSPENDED, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
    }

    @Test
    void authenticateForToken_repositoryFailure_failsClosed() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.error(new RuntimeException("connection refused")));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("repository_error"), anyMapArg());
    }

    @Test
    void authenticateForToken_unknownClientAndWrongSecret_produceIdenticalExceptionMessage() {
        init();
        when(apiClientRepository.findByClientId("unknown-client")).thenReturn(Mono.empty());
        String unknownClientMessage = captureDenialMessage(
                service.authenticateForToken(TENANT, "unknown-client", RAW_SECRET));

        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));
        String wrongSecretMessage = captureDenialMessage(
                service.authenticateForToken(TENANT, CLIENT_ID, "wrong-secret"));

        assertThat(unknownClientMessage).isEqualTo(wrongSecretMessage);
    }

    private String captureDenialMessage(Mono<AuthenticatedApiClient> result) {
        try {
            result.block();
            throw new AssertionError("expected ApiClientAuthenticationException");
        } catch (ApiClientAuthenticationException ex) {
            return ex.getMessage();
        }
    }

    @Test
    void authenticateForToken_deniedPaths_neverIncludeClientSecretInAuditDetails() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        StepVerifier.create(service.authenticateForToken(TENANT, CLIENT_ID, "wrong-secret"))
                .expectError(ApiClientAuthenticationException.class)
                .verify();

        ArgumentCaptor<Map<String, Object>> detailsCaptor = mapCaptor();
        verify(auditService).auditFailure(anyString(), anyString(), anyString(), detailsCaptor.capture());
        assertThat(detailsCaptor.getValue()).doesNotContainKey("client_secret");
        assertThat(detailsCaptor.getValue().values()).noneMatch(v -> RAW_SECRET.equals(v) || "wrong-secret".equals(v));
        verify(auditService, never()).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyMapArg());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> anyMapArg() {
        return org.mockito.ArgumentMatchers.anyMap();
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> mapCaptor() {
        return ArgumentCaptor.forClass(Map.class);
    }
}
