package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.statuslist.domain.exception.AlreadyRevokedException;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationRequestException;
import es.in2.issuer.backend.statuslist.domain.exception.NotRevocableException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Translates the rejections of {@link RevocationController} into the contract of EUD-247: its codes,
 * {@code application/problem+json} and {@code instance} set to the request path. Scoped to that
 * controller so the deprecated alias keeps today's answers (AD-4). Details are fixed: exception
 * messages can name tenants or powers and stay in the log.
 */
@Slf4j
@RestControllerAdvice(assignableTypes = RevocationController.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RevocationExceptionHandler {

    static final String RETRY_AFTER_SECONDS = "5";

    private static final String BAD_REQUEST_TYPE = "BAD_REQUEST";
    private static final String INTERNAL_ERROR_TYPE = "INTERNAL_SERVER_ERROR";

    @ExceptionHandler(InvalidRevocationRequestException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleInvalidRequest(
            InvalidRevocationRequestException ex, ServerHttpRequest request) {
        List<GlobalErrorMessage.FieldViolation> violations = ex.getViolations().stream()
                .map(v -> new GlobalErrorMessage.FieldViolation(v.field(), v.message()))
                .toList();
        return problem(ex, request, HttpStatus.BAD_REQUEST, BAD_REQUEST_TYPE, "Bad request",
                "The request is not valid", violations);
    }

    @ExceptionHandler(IssuanceNotFoundException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleIssuanceNotFound(
            IssuanceNotFoundException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.NOT_FOUND, GlobalErrorTypes.ISSUANCE_NOT_FOUND.getCode(),
                "Issuance not found", "The issuance process does not exist or is outside your scope", null);
    }

    @ExceptionHandler(AlreadyRevokedException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleAlreadyRevoked(
            AlreadyRevokedException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.CONFLICT, GlobalErrorTypes.ALREADY_REVOKED.getCode(),
                "Already revoked", "The attestation is already revoked", null);
    }

    @ExceptionHandler(NotRevocableException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleNotRevocable(
            NotRevocableException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.CONFLICT, GlobalErrorTypes.NOT_REVOCABLE.getCode(),
                "Not revocable", "The attestation cannot be revoked", null);
    }

    @ExceptionHandler(StatusListUnavailableException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleStatusListUnavailable(
            StatusListUnavailableException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.SERVICE_UNAVAILABLE, GlobalErrorTypes.STATUS_LIST_UNAVAILABLE.getCode(),
                "Status list unavailable", "The attestation could not be marked in its status list. Nothing was changed", null)
                .map(response -> ResponseEntity.status(response.getStatusCode())
                        .headers(response.getHeaders())
                        .header(HttpHeaders.RETRY_AFTER, RETRY_AFTER_SECONDS)
                        .body(response.getBody()));
    }

    @ExceptionHandler(InsufficientPermissionException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleInsufficientPermission(
            InsufficientPermissionException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.FORBIDDEN, GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode(),
                "Insufficient permission", "The requester may not revoke this attestation", null);
    }

    @ExceptionHandler(TenantMismatchException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleTenantMismatch(
            TenantMismatchException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.FORBIDDEN, GlobalErrorTypes.TENANT_MISMATCH.getCode(),
                "Tenant mismatch", "The request tenant is not the tenant of the requester's attestation", null);
    }

    @ExceptionHandler(TenantNotResolvedException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleTenantNotResolved(
            TenantNotResolvedException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.FORBIDDEN, GlobalErrorTypes.TENANT_NOT_RESOLVED.getCode(),
                "Tenant not resolved", "No tenant could be resolved for the request", null);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleInvalidToken(
            InvalidTokenException ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.UNAUTHORIZED, GlobalErrorTypes.INVALID_TOKEN.getCode(),
                "Invalid token", "The access token is not valid", null);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleResponseStatus(
            ResponseStatusException ex, ServerHttpRequest request) {
        HttpStatusCode status = ex.getStatusCode();
        HttpStatus resolved = HttpStatus.resolve(status.value());
        String title = resolved != null ? resolved.getReasonPhrase() : "Error";
        String type = resolved != null ? resolved.name() : String.valueOf(status.value());
        return problem(ex, request, status, type, title, title, null);
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleUnexpected(Exception ex, ServerHttpRequest request) {
        return problem(ex, request, HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR_TYPE,
                "Internal server error", "An unexpected error occurred. Nothing was changed", null);
    }

    private Mono<ResponseEntity<GlobalErrorMessage>> problem(
            Exception ex, ServerHttpRequest request, HttpStatusCode status, String type, String title, String detail,
            List<GlobalErrorMessage.FieldViolation> violations) {
        String instance = request.getPath().pathWithinApplication().value();
        if (status.is5xxServerError()) {
            log.error("path={} status={} type={}", instance, status.value(), type, ex);
        } else {
            log.info("path={} status={} type={} ex={}", instance, status.value(), type, ex.getClass().getSimpleName());
        }
        GlobalErrorMessage body = new GlobalErrorMessage(type, title, status.value(), detail, instance, violations);
        return Mono.just(ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(body));
    }
}
