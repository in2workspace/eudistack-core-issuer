package es.in2.issuer.backend.shared.web.exception;

import es.in2.issuer.backend.dome.domain.exception.InvalidIdempotencyKeyException;
import es.in2.issuer.backend.dome.domain.exception.TenantNotConfiguredException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.util.concurrent.TimeoutException;

import org.springframework.core.annotation.Order;
import org.springframework.core.Ordered;

/**
 * Global exception handler for DOME Sync Credentials operations.
 * Maps backend exceptions to RFC 9457 Problem+JSON responses.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DomeSyncExceptionHandler {

    @ExceptionHandler(TenantNotConfiguredException.class)
    public ProblemDetail handleTenantNotConfigured(TenantNotConfiguredException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage());
        problem.setTitle("Tenant Not Configured");
        problem.setType(URI.create("https://eudistack.org/errors/tenant-not-configured"));
        return problem;
    }

    @ExceptionHandler(InvalidIdempotencyKeyException.class)
    public ProblemDetail handleInvalidIdempotencyKey(InvalidIdempotencyKeyException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setTitle("Invalid Idempotency Key");
        problem.setType(URI.create("https://eudistack.org/errors/invalid-idempotency-key"));
        return problem;
    }

    @ExceptionHandler(DataAccessResourceFailureException.class)
    public ProblemDetail handleDatabaseFailure(DataAccessResourceFailureException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "Database connection failure during synchronization.");
        problem.setTitle("Data Access Resource Failure");
        return problem;
    }

    @ExceptionHandler(TimeoutException.class)
    public ProblemDetail handleTimeout(TimeoutException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.GATEWAY_TIMEOUT, "The operation timed out while resolving credentials.");
        problem.setTitle("Gateway Timeout");
        return problem;
    }
}