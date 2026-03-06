package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.OAuthErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
@RestControllerAdvice
public class Oidc4vciExceptionHandler {

    @ExceptionHandler(OAuthTokenException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<OAuthErrorResponse> handleOAuthTokenException(OAuthTokenException ex) {
        log.warn("OAuth token error: error={}, description={}", ex.getErrorCode(), ex.getMessage());
        return Mono.just(new OAuthErrorResponse(ex.getErrorCode(), ex.getMessage()));
    }
}