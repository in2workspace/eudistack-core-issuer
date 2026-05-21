package es.in2.issuer.backend.dome.infrastructure.controller;

import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.exception.HashMismatchException;
import es.in2.issuer.backend.dome.domain.exception.KmsAliasNotProvisionedException;
import es.in2.issuer.backend.dome.domain.exception.PostImportValidationFailedException;
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
@Order(3)
public class KeyMigrationExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(ConflictingMigrationStateException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleConflictingMigrationStateException(
            ConflictingMigrationStateException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                "conflicting_migration_state",
                "Migration state conflict",
                HttpStatus.CONFLICT,
                "The migration record is already in a terminal state that prevents this transition"
        );
    }

    @ExceptionHandler(KmsAliasNotProvisionedException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Mono<GlobalErrorMessage> handleKmsAliasNotProvisionedException(
            KmsAliasNotProvisionedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                "kms_alias_not_provisioned",
                "KMS alias not available",
                HttpStatus.SERVICE_UNAVAILABLE,
                "The target KMS alias has not been provisioned"
        );
    }

    @ExceptionHandler(PostImportValidationFailedException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handlePostImportValidationFailedException(
            PostImportValidationFailedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                "post_import_validation_failed",
                "Post-import validation failed",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The signature produced after key import could not be verified"
        );
    }

    @ExceptionHandler(HashMismatchException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleHashMismatchException(
            HashMismatchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                "hash_mismatch",
                "Credential hash mismatch",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The hash of the re-issued credential does not match the original credential hash"
        );
    }
}

