package es.in2.issuer.backend.shared.infrastructure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionFailedException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionRequiredException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage.FieldViolation;
import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.Order;
import org.springframework.core.codec.DecodingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * Errors of the Attestation Catalogue API and of its deprecated alias
 * ({@link CredentialCatalogController}) as {@code application/problem+json} (RFC 9457), with the
 * {@code type} codes of the contract and {@code instance} = the path the client called, context path
 * included (D11).
 *
 * <p>It runs before {@link SharedExceptionHandler} and {@code IssuanceExceptionHandler} and, because it
 * ends in a catch-all, it answers every error of these two controllers: nothing falls back to their
 * {@code application/json} shape. So it also maps what the alias used to leave to the shared advice.
 * Other controllers keep their own error format.
 */
@RestControllerAdvice(assignableTypes = {AttestationCatalogController.class, CredentialCatalogController.class})
@Order(1)
@RequiredArgsConstructor
public class CatalogExceptionHandler {

    /** The violation field of a body that cannot be read as a whole. */
    private static final String BODY = "body";

    private final ErrorResponseFactory errors;

    // ---- the catalog contract ----------------------------------------------------

    /** {@code BAD_REQUEST}, {@code unknown_schema}, {@code unsupported_binding_type}, {@code field_not_in_schema}, ... */
    @ExceptionHandler(CatalogConfigurationException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleCatalogConfiguration(
            CatalogConfigurationException ex, ServerHttpRequest request) {
        List<FieldViolation> violations = ex.violations().stream()
                .map(v -> new FieldViolation(v.field(), v.message()))
                .toList();
        String title = CatalogConfigurationException.BAD_REQUEST.equals(ex.code())
                ? HttpStatus.BAD_REQUEST.getReasonPhrase()
                : humanize(ex.code());
        return problem(ex, request, ex.code(), title, HttpStatus.BAD_REQUEST, ex.getMessage(), violations);
    }

    @ExceptionHandler(CatalogEntryNotFoundException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleNotFound(
            CatalogEntryNotFoundException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.CATALOG_ENTRY_NOT_FOUND.getCode(),
                "Catalog entry not found", HttpStatus.NOT_FOUND, ex.getMessage(), null);
    }

    @ExceptionHandler(CatalogEntryAlreadyExistsException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleAlreadyExists(
            CatalogEntryAlreadyExistsException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.CATALOG_ENTRY_ALREADY_EXISTS.getCode(),
                "Catalog entry already exists", HttpStatus.CONFLICT, ex.getMessage(), null);
    }

    @ExceptionHandler(PreconditionFailedException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handlePreconditionFailed(
            PreconditionFailedException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.PRECONDITION_FAILED.getCode(),
                "Precondition failed", HttpStatus.PRECONDITION_FAILED, ex.getMessage(), null);
    }

    @ExceptionHandler(PreconditionRequiredException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handlePreconditionRequired(
            PreconditionRequiredException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.PRECONDITION_REQUIRED.getCode(),
                "Precondition required", HttpStatus.PRECONDITION_REQUIRED, ex.getMessage(), null);
    }

    // ---- authentication and authorization ----------------------------------------

    /** Thrown inside the controller by the token service, not by the security chain. */
    @ExceptionHandler(InvalidTokenException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleInvalidToken(
            InvalidTokenException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.INVALID_TOKEN.getCode(), "Invalid token",
                HttpStatus.UNAUTHORIZED, "The access token is missing or not valid", null);
    }

    /** The detail is the PDP's own, the shared handler's one talks about issuance. */
    @ExceptionHandler(InsufficientPermissionException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleInsufficientPermission(
            InsufficientPermissionException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode(), "Insufficient permission",
                HttpStatus.FORBIDDEN, ex.getMessage(), null);
    }

    @ExceptionHandler(TenantMismatchException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleTenantMismatch(
            TenantMismatchException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.TENANT_MISMATCH.getCode(), "Tenant mismatch",
                HttpStatus.FORBIDDEN, "The token's organization does not match the requested tenant", null);
    }

    @ExceptionHandler(TenantNotResolvedException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleTenantNotResolved(
            TenantNotResolvedException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.TENANT_NOT_RESOLVED.getCode(), "Tenant not resolved",
                HttpStatus.FORBIDDEN, ex.getMessage(), null);
    }

    // ---- request that cannot be read ---------------------------------------------
    // WebExchangeBindException and ServerWebInputException are ResponseStatusExceptions: each has its own
    // handler so that none of them ends up in the generic one below.

    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleBind(WebExchangeBindException ex, ServerHttpRequest request) {
        List<FieldViolation> violations = Stream.concat(
                        ex.getFieldErrors().stream()
                                .map(error -> new FieldViolation(error.getField(), String.valueOf(error.getDefaultMessage()))),
                        ex.getGlobalErrors().stream()
                                .map(error -> new FieldViolation(error.getObjectName(), String.valueOf(error.getDefaultMessage()))))
                .toList();
        return problem(ex, request, CatalogConfigurationException.BAD_REQUEST, HttpStatus.BAD_REQUEST.getReasonPhrase(),
                HttpStatus.BAD_REQUEST, "The request body is not valid", violations);
    }

    /** A missing header or body, a parameter of the wrong type, or a body Jackson could not read. */
    @ExceptionHandler(ServerWebInputException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleServerWebInput(
            ServerWebInputException ex, ServerHttpRequest request) {
        List<FieldViolation> violations = decodingViolations(ex);
        if (violations == null && isMissingBody(ex)) {
            violations = List.of(new FieldViolation(BODY, "is required"));
        }
        return problem(ex, request, CatalogConfigurationException.BAD_REQUEST, HttpStatus.BAD_REQUEST.getReasonPhrase(),
                HttpStatus.BAD_REQUEST, ex.getReason(), violations);
    }

    @ExceptionHandler(DecodingException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleDecoding(DecodingException ex, ServerHttpRequest request) {
        return problem(ex, request, CatalogConfigurationException.BAD_REQUEST, HttpStatus.BAD_REQUEST.getReasonPhrase(),
                HttpStatus.BAD_REQUEST, "The request body could not be read", decodingViolations(ex));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleResponseStatus(
            ResponseStatusException ex, ServerHttpRequest request) {
        HttpStatus status = HttpStatus.resolve(ex.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        GlobalErrorMessage problem = errors.problemOf(ex, request, status.name(), status.getReasonPhrase(), status,
                ex.getReason() != null ? ex.getReason() : status.getReasonPhrase(), null);
        return Mono.just(ResponseEntity.status(status)
                .headers(ex.getHeaders())
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem));
    }

    // ---- errors the deprecated alias had before ----------------------------------

    @ExceptionHandler(CredentialCatalogNotConfiguredException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleCatalogNotConfigured(
            CredentialCatalogNotConfiguredException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.CREDENTIAL_CATALOG_NOT_CONFIGURED.getCode(),
                "Credential catalog not configured", HttpStatus.NOT_FOUND, ex.getMessage(), null);
    }

    @ExceptionHandler(UnknownCredentialConfigurationException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleUnknownCredentialConfiguration(
            UnknownCredentialConfigurationException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.UNKNOWN_CREDENTIAL_CONFIGURATION.getCode(),
                "Unknown credential configuration", HttpStatus.BAD_REQUEST, ex.getMessage(), null);
    }

    @ExceptionHandler(InvalidDeliveryConfigException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleInvalidDeliveryConfig(
            InvalidDeliveryConfigException ex, ServerHttpRequest request) {
        return problem(ex, request, GlobalErrorTypes.INVALID_DELIVERY_CONFIG.getCode(),
                "Invalid delivery configuration", HttpStatus.BAD_REQUEST, ex.getMessage(), null);
    }

    /**
     * D8: a delivery mode above the schema ceiling is a {@code BAD_REQUEST}, not the 409
     * {@code delivery_mode_not_eligible} the alias answered before (the contract has no such code). The
     * alias body keys its modes by credential configuration id, so the violation names that member; the
     * message names the mode and the type.
     */
    @ExceptionHandler(DeliveryModeNotEligibleException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleDeliveryModeNotEligible(
            DeliveryModeNotEligibleException ex, ServerHttpRequest request) {
        return problem(ex, request, CatalogConfigurationException.BAD_REQUEST, HttpStatus.BAD_REQUEST.getReasonPhrase(),
                HttpStatus.BAD_REQUEST, "The request body is not valid",
                List.of(new FieldViolation("deliveryModesByConfigurationId", ex.getMessage())));
    }

    // ---- everything else ---------------------------------------------------------

    /** SEC-13: never leaks the exception message. */
    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleUnexpected(Exception ex, ServerHttpRequest request) {
        return problem(ex, request, "INTERNAL_SERVER_ERROR", "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", null);
    }

    // ---- helpers -----------------------------------------------------------------

    private Mono<ResponseEntity<GlobalErrorMessage>> problem(
            Exception ex, ServerHttpRequest request, String type, String title, HttpStatus status, String detail,
            List<FieldViolation> violations) {
        GlobalErrorMessage problem = errors.problemOf(ex, request, type, title, status, detail, violations);
        return Mono.just(ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem));
    }

    /**
     * When Jackson rejected a value of the body (a string where a number goes, an object where a list goes)
     * the violation names it by its path, as the API spells it ({@code validity.default_days},
     * {@code search_identifiers[0]}). A body that is not JSON at all, or whose value has no path (a list
     * where the object goes), is a violation on {@code body}. Nothing of Jackson's own message is sent.
     * Null when the failure was not about the body.
     */
    private static List<FieldViolation> decodingViolations(Throwable ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof JsonMappingException mapping) {
                String field = apiPath(mapping);
                return List.of(new FieldViolation(field.isEmpty() ? BODY : field, "has an invalid value"));
            }
            if (cause instanceof JsonProcessingException) {
                return List.of(new FieldViolation(BODY, "is not valid JSON"));
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return null;
    }

    /**
     * Spring's failure for an empty body that is required: about the {@code @RequestBody} parameter, with
     * the reason {@code No request body} (Spring has no constant for it; its cause is a non-Jackson
     * {@code DecodingException}). A missing header or a query or path parameter of the wrong type is about
     * another parameter, and a body that failed to decode has another reason.
     */
    private static boolean isMissingBody(ServerWebInputException ex) {
        MethodParameter parameter = ex.getMethodParameter();
        return parameter != null && parameter.hasParameterAnnotation(RequestBody.class)
                && "No request body".equals(ex.getReason());
    }

    private static String apiPath(JsonMappingException mapping) {
        StringBuilder field = new StringBuilder();
        for (JsonMappingException.Reference step : mapping.getPath()) {
            if (step.getFieldName() != null) {
                field.append(field.isEmpty() ? "" : ".").append(step.getFieldName());
            } else if (step.getIndex() >= 0) {
                field.append('[').append(step.getIndex()).append(']');
            }
        }
        return field.toString();
    }

    /** {@code field_not_in_schema} to {@code Field not in schema}. */
    private static String humanize(String code) {
        String words = code.replace('_', ' ').toLowerCase(Locale.ROOT);
        return Character.toUpperCase(words.charAt(0)) + words.substring(1);
    }
}
