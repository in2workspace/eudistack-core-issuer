package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
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

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        nonceService = mock(NonceService.class);
        handler = new Oidc4vciExceptionHandler(errors, nonceService);
        request = MockServerHttpRequest.get("/any").build();
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

        StepVerifier.create(handler.handleOAuthTokenException(ex))
                .assertNext(response -> {
                    assertEquals("invalid_grant", response.error());
                    assertEquals("The grant is invalid", response.errorDescription());
                })
                .verifyComplete();
    }

    // -------------------- handleInvalidOrMissingProof --------------------

    @Test
    void handleInvalidOrMissingProof_includesNonceInResponse() {
        var ex = new InvalidOrMissingProofException("bad proof");
        var type = GlobalErrorTypes.INVALID_OR_MISSING_PROOF.getCode();
        var title = "Invalid or missing proof";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce.";
        var baseGem = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        var nonce = NonceResponse.builder().cNonce("test-nonce-123").cNonceExpiresIn(600).build();

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(baseGem));
        when(nonceService.issueNonce()).thenReturn(Mono.just(nonce));

        StepVerifier.create(handler.handleInvalidOrMissingProof(ex, request))
                .assertNext(gem -> {
                    assertGem(gem, type, title, st, "bad proof");
                    assertEquals("test-nonce-123", gem.cNonce());
                    assertEquals(600L, gem.cNonceExpiresIn());
                })
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
        verify(nonceService).issueNonce();
    }

    // -------------------- handleProofValidationException --------------------

    @Test
    void handleProofValidationException() {
        var ex = new ProofValidationException("proof invalid");
        var type = GlobalErrorTypes.PROOF_VALIDATION_ERROR.getCode();
        var title = "Proof validation error";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The provided proof is invalid.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "proof invalid", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleProofValidationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "proof invalid"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

}
