package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.oidc4vci.domain.exception.UnknownCredentialIdentifierException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class Oidc4vciExceptionHandlerTest {

    private ErrorResponseFactory errors;
    private NonceService nonceService;
    private Oidc4vciExceptionHandler handler;
    private ServerHttpRequest request;
    private ServerHttpResponse response;

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        nonceService = mock(NonceService.class);
        handler = new Oidc4vciExceptionHandler(errors, nonceService);
        request = MockServerHttpRequest.get("/any").build();
        response = new MockServerHttpResponse();
    }

    private void assertGem(GlobalErrorMessage gem,
                           String expectedType,
                           String expectedTitle,
                           HttpStatus expectedStatus,
                           String expectedDetail) {
        assertEquals(expectedType, gem.type());
        assertEquals(expectedTitle, gem.title());
        assertEquals(expectedStatus.value(), gem.status());
        assertEquals(expectedDetail, gem.detail());
        assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
    }

    // -------------------- handleOAuthTokenException --------------------

    @Test
    void handleOAuthTokenException_returnsBadRequest() {
        var ex = new OAuthTokenException("invalid_grant", "The grant is invalid");

        StepVerifier.create(handler.handleOAuthTokenException(ex, response))
                .assertNext(body -> {
                    assertEquals("invalid_grant", body.error());
                    assertEquals("The grant is invalid", body.errorDescription());
                })
                .verifyComplete();
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void handleOAuthTokenException_invalidClient_returnsUnauthorized() {
        var ex = OAuthTokenException.invalidClient();

        StepVerifier.create(handler.handleOAuthTokenException(ex, response))
                .assertNext(body -> {
                    assertEquals("invalid_client", body.error());
                    assertEquals("invalid_client", body.errorDescription());
                })
                .verifyComplete();
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    // -------------------- handleInvalidOrMissingProof --------------------

    @Test
    void handleInvalidOrMissingProof_returnsCredentialErrorResponseWithNonce() {
        var ex = new InvalidOrMissingProofException("bad proof");
        var nonce = NonceResponse.builder().cNonce("test-nonce-123").cNonceExpiresIn(600).build();

        when(nonceService.issueNonce()).thenReturn(Mono.just(nonce));

        StepVerifier.create(handler.handleInvalidOrMissingProof(ex))
                .assertNext(body -> {
                    assertEquals("invalid_proof", body.error());
                    assertEquals("bad proof", body.errorDescription());
                    assertEquals("test-nonce-123", body.cNonce());
                    assertEquals(600L, body.cNonceExpiresIn());
                })
                .verifyComplete();

        verify(nonceService).issueNonce();
    }

    // -------------------- handleProofValidationException --------------------

    @Test
    void handleProofValidationException_returnsCredentialErrorResponseWithNonce() {
        var ex = new ProofValidationException("proof invalid");
        var nonce = NonceResponse.builder().cNonce("test-nonce-456").cNonceExpiresIn(600).build();

        when(nonceService.issueNonce()).thenReturn(Mono.just(nonce));

        StepVerifier.create(handler.handleProofValidationException(ex))
                .assertNext(body -> {
                    assertEquals("invalid_proof", body.error());
                    assertEquals("proof invalid", body.errorDescription());
                    assertEquals("test-nonce-456", body.cNonce());
                    assertEquals(600L, body.cNonceExpiresIn());
                })
                .verifyComplete();

        verify(nonceService).issueNonce();
    }

    // -------------------- handleUnknownCredentialConfiguration --------------------

    @Test
    void handleUnknownCredentialConfiguration_returnsCredentialErrorResponseWithoutNonce() {
        var ex = new UnknownCredentialConfigurationException("Unknown credential_configuration_id: bogus");

        StepVerifier.create(handler.handleUnknownCredentialConfiguration(ex))
                .assertNext(body -> {
                    assertEquals("unknown_credential_configuration", body.error());
                    assertEquals("Unknown credential_configuration_id: bogus", body.errorDescription());
                    assertEquals(null, body.cNonce());
                    assertEquals(null, body.cNonceExpiresIn());
                })
                .verifyComplete();

        verifyNoInteractions(nonceService);
    }

    // -------------------- handleUnknownCredentialIdentifier --------------------

    @Test
    void handleUnknownCredentialIdentifier_returnsCredentialErrorResponseWithoutNonce() {
        var ex = new UnknownCredentialIdentifierException("Unknown credential_identifier: bogus");

        StepVerifier.create(handler.handleUnknownCredentialIdentifier(ex))
                .assertNext(body -> {
                    assertEquals("unknown_credential_identifier", body.error());
                    assertEquals("Unknown credential_identifier: bogus", body.errorDescription());
                    assertEquals(null, body.cNonce());
                    assertEquals(null, body.cNonceExpiresIn());
                })
                .verifyComplete();

        verifyNoInteractions(nonceService);
    }

    // -------------------- handleIllegalArgumentException --------------------

    @Test
    void handleIllegalArgumentException_returnsBadRequest() {
        var ex = new IllegalArgumentException("Missing DPoP proof");
        var type = GlobalErrorTypes.INVALID_REQUEST.getCode();
        var title = "Invalid request";
        var st = HttpStatus.BAD_REQUEST;
        var expected = new GlobalErrorMessage(type, title, st.value(), "Missing DPoP proof", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, "Missing DPoP proof")).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleIllegalArgumentException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Missing DPoP proof"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, "Missing DPoP proof");
    }

}
