package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.OAuthErrorResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
@Order(1)
public class Oidc4vciExceptionHandler {

    private final ErrorResponseFactory errors;
    private final NonceService nonceService;

    @ExceptionHandler(OAuthTokenException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<OAuthErrorResponse> handleOAuthTokenException(OAuthTokenException ex) {
        log.warn("OAuth token error: error={}, description={}", ex.getErrorCode(), ex.getMessage());
        return Mono.just(new OAuthErrorResponse(ex.getErrorCode(), ex.getMessage()));
    }

    @ExceptionHandler(InvalidOrMissingProofException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidOrMissingProof(
            InvalidOrMissingProofException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_OR_MISSING_PROOF.getCode(),
                "Invalid or missing proof",
                HttpStatus.BAD_REQUEST,
                "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."
        ).flatMap(gem -> nonceService.issueNonce()
                .map(nonce -> gem.withNonce(nonce.cNonce(), nonce.cNonceExpiresIn())));
    }

    @ExceptionHandler(ProofValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleProofValidationException(
            ProofValidationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PROOF_VALIDATION_ERROR.getCode(),
                "Proof validation error",
                HttpStatus.BAD_REQUEST,
                "The provided proof is invalid."
        );
    }
}