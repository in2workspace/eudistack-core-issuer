package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialControllerTest {

    private static final String PUBLIC_BASE_URL = "https://test.example/issuer";

    @Mock
    private Oid4VciCredentialWorkflow oid4VciCredentialWorkflow;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private UrlResolver urlResolver;

    @Mock
    private DpopValidationService dpopValidationService;

    @InjectMocks
    private CredentialController credentialController;

    private static ServerWebExchange newExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.post("/oid4vci/v1/credential"));
    }

    @Test
    void issueCredential_whenTransactionIdPresent_returnsAccepted() {
        String authorizationHeader = "Bearer testToken";
        ServerWebExchange exchange = newExchange();

        CredentialRequest credentialRequest = CredentialRequest.builder()
                .credentialConfigurationId("sampleFormat")
                .build();

        CredentialResponse credentialResponse = CredentialResponse.builder()
                .credentials(List.of(
                        CredentialResponse.Credential.builder()
                                .credential("sampleCredential")
                                .build()))
                .transactionId("sampleTransactionId")
                .build();

        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "testToken",
                "jti-123",
                "proc-123",
                null
        );

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(accessTokenService.resolveAccessTokenContext(authorizationHeader))
                .thenReturn(Mono.just(accessTokenContext));
        when(oid4VciCredentialWorkflow.createCredentialResponse(
                anyString(), eq(credentialRequest), eq(accessTokenContext), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.just(credentialResponse));

        Mono<ResponseEntity<CredentialResponse>> result =
                credentialController.issueCredential(authorizationHeader, null, credentialRequest, exchange);

        StepVerifier.create(result)
                .assertNext(response -> {
                    assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
                    assertEquals(credentialResponse, response.getBody());
                })
                .verifyComplete();
    }

    @Test
    void issueCredential_whenNoTransactionId_returnsOk() {
        String authorizationHeader = "Bearer testToken";
        ServerWebExchange exchange = newExchange();

        CredentialRequest credentialRequest = CredentialRequest.builder()
                .credentialConfigurationId("sampleFormat")
                .build();

        CredentialResponse credentialResponse = CredentialResponse.builder()
                .credentials(List.of(
                        CredentialResponse.Credential.builder()
                                .credential("sampleCredential")
                                .build()))
                .transactionId(null)
                .build();

        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "testToken",
                "jti-123",
                "proc-123",
                null
        );

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(accessTokenService.resolveAccessTokenContext(authorizationHeader))
                .thenReturn(Mono.just(accessTokenContext));
        when(oid4VciCredentialWorkflow.createCredentialResponse(
                anyString(), eq(credentialRequest), eq(accessTokenContext), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.just(credentialResponse));

        Mono<ResponseEntity<CredentialResponse>> result =
                credentialController.issueCredential(authorizationHeader, null, credentialRequest, exchange);

        StepVerifier.create(result)
                .assertNext(response -> {
                    assertEquals(HttpStatus.OK, response.getStatusCode());
                    assertEquals(credentialResponse, response.getBody());
                })
                .verifyComplete();
    }

    // -------------------- DPoP binding (RFC 9449 §5-7) --------------------

    @Test
    void issueCredential_whenDpopBoundTokenMissingDpopHeader_returnsError() {
        String authorizationHeader = "DPoP testToken";
        ServerWebExchange exchange = newExchange();

        CredentialRequest credentialRequest = CredentialRequest.builder()
                .credentialConfigurationId("sampleFormat")
                .build();

        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "testToken", "jti-123", "proc-123", "expected-jkt"
        );

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(accessTokenService.resolveAccessTokenContext(authorizationHeader))
                .thenReturn(Mono.just(accessTokenContext));

        Mono<ResponseEntity<CredentialResponse>> result =
                credentialController.issueCredential(authorizationHeader, null, credentialRequest, exchange);

        StepVerifier.create(result)
                .expectError(InvalidTokenException.class)
                .verify();

        verify(dpopValidationService, never()).validate(anyString(), anyString(), anyString(), anyString());
        verify(oid4VciCredentialWorkflow, never()).createCredentialResponse(anyString(), any(), any(), anyString());
    }

    @Test
    void issueCredential_whenDpopKeyMismatch_returnsError() {
        String authorizationHeader = "DPoP testToken";
        String dpopHeader = "dpop-proof-jwt";
        ServerWebExchange exchange = newExchange();

        CredentialRequest credentialRequest = CredentialRequest.builder()
                .credentialConfigurationId("sampleFormat")
                .build();

        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "testToken", "jti-123", "proc-123", "expected-jkt"
        );

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(accessTokenService.resolveAccessTokenContext(authorizationHeader))
                .thenReturn(Mono.just(accessTokenContext));
        when(dpopValidationService.validate(eq(dpopHeader), eq("POST"), anyString(), eq("testToken")))
                .thenReturn("different-jkt");

        Mono<ResponseEntity<CredentialResponse>> result =
                credentialController.issueCredential(authorizationHeader, dpopHeader, credentialRequest, exchange);

        StepVerifier.create(result)
                .expectError(InvalidTokenException.class)
                .verify();

        verify(oid4VciCredentialWorkflow, never()).createCredentialResponse(anyString(), any(), any(), anyString());
    }

    @Test
    void issueCredential_whenDpopKeyMatches_succeeds() {
        String authorizationHeader = "DPoP testToken";
        String dpopHeader = "dpop-proof-jwt";
        ServerWebExchange exchange = newExchange();

        CredentialRequest credentialRequest = CredentialRequest.builder()
                .credentialConfigurationId("sampleFormat")
                .build();

        CredentialResponse credentialResponse = CredentialResponse.builder()
                .credentials(List.of(
                        CredentialResponse.Credential.builder()
                                .credential("sampleCredential")
                                .build()))
                .transactionId(null)
                .build();

        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "testToken", "jti-123", "proc-123", "matching-jkt"
        );

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(accessTokenService.resolveAccessTokenContext(authorizationHeader))
                .thenReturn(Mono.just(accessTokenContext));
        when(dpopValidationService.validate(eq(dpopHeader), eq("POST"), anyString(), eq("testToken")))
                .thenReturn("matching-jkt");
        when(oid4VciCredentialWorkflow.createCredentialResponse(
                anyString(), eq(credentialRequest), eq(accessTokenContext), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.just(credentialResponse));

        Mono<ResponseEntity<CredentialResponse>> result =
                credentialController.issueCredential(authorizationHeader, dpopHeader, credentialRequest, exchange);

        StepVerifier.create(result)
                .assertNext(response -> {
                    assertEquals(HttpStatus.OK, response.getStatusCode());
                    assertEquals(credentialResponse, response.getBody());
                })
                .verifyComplete();
    }
}
