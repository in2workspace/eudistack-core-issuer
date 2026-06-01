package es.in2.issuer.backend.dome.infrastructure.controller;

import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.exception.HashMismatchException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@RestControllerAdvice
@Profile("key-migration")
@RequiredArgsConstructor
@Slf4j
@Order(3)
public class KeyMigrationExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(ConflictingMigrationStateException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleConflictingMigrationState(
            ConflictingMigrationStateException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                "CONFLICTING_MIGRATION_STATE",
                "Conflicting migration state",
                HttpStatus.CONFLICT,
                "The migration state transition is not allowed"
        );
    }

    @ExceptionHandler(HashMismatchException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleHashMismatch(
            HashMismatchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                "KEY_MATERIAL_VALIDATION_FAILURE",
                "Key material validation failure",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The exported key material failed signature self-verification"
        );
    }
}

