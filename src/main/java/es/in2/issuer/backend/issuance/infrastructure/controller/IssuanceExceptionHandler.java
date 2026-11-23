package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalTenantMismatchException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.shared.domain.exception.AuditTrailUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidGrantTypeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidValidityException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.issuance.domain.exception.UnknownOrganizationException;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryFailedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
@RestControllerAdvice
@Order(2)
public class IssuanceExceptionHandler {

    /** Seconds a client waits before retrying a renewal whose delivery failed. */
    private static final int RENEWAL_RETRY_AFTER_SECONDS = 30;

    private final ErrorResponseFactory errors;
    /** {@code Retry-After} of a delivery that failed because a dependency was temporarily unavailable. */
    private final int deliveryRetryAfterSeconds;

    // A plain property rather than IssuanceProperties: every @WebFluxTest slice loads this advice, and
    // the slices do not bind configuration properties.
    public IssuanceExceptionHandler(
            ErrorResponseFactory errors,
            @Value("${issuance.delivery-retry-after-seconds:5}") int deliveryRetryAfterSeconds) {
        this.errors = errors;
        this.deliveryRetryAfterSeconds = deliveryRetryAfterSeconds;
    }

    @ExceptionHandler(InvalidStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleInvalidStatusException(
            InvalidStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_STATUS.getCode(),
                "Invalid status",
                HttpStatus.CONFLICT,
                "The entity is not in a valid status for this operation"
        );
    }

    /** EUD-255: a query that is not valid, with one violation per field and never its value (AD-5). */
    @ExceptionHandler(InvalidQueryException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidQuery(
            InvalidQueryException ex,
            ServerHttpRequest request
    ) {
        var violations = ex.violations().stream()
                .map(v -> new GlobalErrorMessage.FieldViolation(v.field(), v.message()))
                .toList();
        return errors.handleWithViolations(
                ex, request,
                GlobalErrorTypes.INVALID_REQUEST.getCode(),
                "Invalid request",
                HttpStatus.BAD_REQUEST,
                "The query is not valid",
                violations
        );
    }

    /**
     * EUD-255 AD-7: a read whose trace could not be staged. Nothing of the read is returned, and the detail is
     * fixed: neither the business outcome (a refusal included) nor the cause reaches the client.
     */
    @ExceptionHandler(AuditTrailUnavailableException.class)
    public ResponseEntity<GlobalErrorMessage> handleAuditTrailUnavailable(
            AuditTrailUnavailableException ex,
            ServerHttpRequest request
    ) {
        return errors.problem(ex, request, GlobalErrorTypes.INTERNAL_ERROR.getCode(), "Internal error",
                HttpStatus.INTERNAL_SERVER_ERROR, "The request could not be completed", null);
    }

    @ExceptionHandler(InvalidDeliveryModeException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidDeliveryMode(
            InvalidDeliveryModeException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_DELIVERY_MODE.getCode(),
                "Invalid delivery mode",
                HttpStatus.BAD_REQUEST,
                "delivery must be one of: email, ui, direct"
        );
    }

    // Also mapped in SharedExceptionHandler (EUD-168 code review): the exception itself lives in the
    // shared package and is thrown by both the issuance path and the credential-catalog PUT
    // (EUD-169; the backoffice delivery-config module this comment used to name was retired), which
    // does not go through this advice in isolated (non-Spring-context) test setups such as
    // DirectDeliveryCeilingTest -- kept here too so the issuance path's own tests stay decoupled from
    // SharedExceptionHandler.
    @ExceptionHandler(DeliveryModeNotEligibleException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleDeliveryModeNotEligible(
            DeliveryModeNotEligibleException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.DELIVERY_MODE_NOT_ELIGIBLE.getCode(),
                "Delivery mode not eligible",
                HttpStatus.CONFLICT,
                "The declared delivery mode is not eligible for this credential type"
        );
    }

    /** EUD-254 AC-18. The detail never echoes the identifier sent: only who may indicate one gets this far. */
    @ExceptionHandler(UnknownOrganizationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleUnknownOrganization(
            UnknownOrganizationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNKNOWN_ORGANIZATION.getCode(),
                "Unknown organization",
                HttpStatus.BAD_REQUEST,
                "organization is not an organization of the tenant"
        );
    }

    @ExceptionHandler(InvalidGrantTypeException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidGrantType(
            InvalidGrantTypeException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_GRANT_TYPE.getCode(),
                "Invalid grant type",
                HttpStatus.BAD_REQUEST,
                "grant_type must be one of: authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code"
        );
    }

    @ExceptionHandler(InvalidValidityException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidValidity(
            InvalidValidityException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_VALIDITY.getCode(),
                "Invalid validity",
                HttpStatus.BAD_REQUEST,
                "The requested validity is not allowed for this attestation type"
        );
    }

    /**
     * EUD-254 AC-03: a valid request whose delivery could not be completed. A dependency that is
     * temporarily unavailable is 503 with {@code Retry-After} -- the client retries with the same
     * {@code X-Idempotency-Key} -- and any other failure is 500. The detail is fixed: the cause's
     * message never reaches the client.
     */
    @ExceptionHandler(DeliveryFailedException.class)
    public Mono<ResponseEntity<GlobalErrorMessage>> handleDeliveryFailed(
            DeliveryFailedException ex,
            ServerHttpRequest request
    ) {
        DeliveryErrorCode code = ex.code();
        HttpStatus status = code.retryable() ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.INTERNAL_SERVER_ERROR;
        String detail = code.retryable()
                ? "The issuance could not be completed. Retry later."
                : "The issuance could not be completed.";
        GlobalErrorMessage problem = errors.problemOf(ex, request, code.value(), code.title(), status, detail, null);
        ResponseEntity.BodyBuilder response = ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON);
        if (code.retryable()) {
            response.header(HttpHeaders.RETRY_AFTER, String.valueOf(deliveryRetryAfterSeconds));
        }
        return Mono.just(response.body(problem));
    }

    @ExceptionHandler(InvalidHolderKeyException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidHolderKey(
            InvalidHolderKeyException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_HOLDER_KEY.getCode(),
                "Invalid holder key",
                HttpStatus.BAD_REQUEST,
                "The holder key is missing or is not an EC P-256 public JWK"
        );
    }

    // ── Renewal of the credential offer (EUD-295): application/problem+json ──────────────────
    // Fixed details, never the exception message: the 404 must not tell an issuance outside the
    // requester's scope from one that does not exist, nor repeat the id.

    @ExceptionHandler(RenewalInvalidIssuanceIdException.class)
    public ResponseEntity<GlobalErrorMessage> handleRenewalInvalidIssuanceId(
            RenewalInvalidIssuanceIdException ex, ServerHttpRequest request) {
        return errors.problem(ex, request, GlobalErrorTypes.BAD_REQUEST.getCode(), "Bad request",
                HttpStatus.BAD_REQUEST, "The issuance id is not a valid UUID", null);
    }

    @ExceptionHandler(RenewalTenantMismatchException.class)
    public ResponseEntity<GlobalErrorMessage> handleRenewalTenantMismatch(
            RenewalTenantMismatchException ex, ServerHttpRequest request) {
        return errors.problem(ex, request, GlobalErrorTypes.TENANT_MISMATCH.getCode(), "Tenant mismatch",
                HttpStatus.FORBIDDEN, "The token's organization does not match the requested tenant", null);
    }

    @ExceptionHandler(RenewalPermissionDeniedException.class)
    public ResponseEntity<GlobalErrorMessage> handleRenewalPermissionDenied(
            RenewalPermissionDeniedException ex, ServerHttpRequest request) {
        return errors.problem(ex, request, GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode(),
                "Insufficient permission", HttpStatus.FORBIDDEN,
                "The requester is not allowed to renew credential offers", null);
    }

    @ExceptionHandler(RenewalIssuanceNotFoundException.class)
    public ResponseEntity<GlobalErrorMessage> handleRenewalIssuanceNotFound(
            RenewalIssuanceNotFoundException ex, ServerHttpRequest request) {
        return errors.problem(ex, request, GlobalErrorTypes.ISSUANCE_NOT_FOUND.getCode(), "Issuance not found",
                HttpStatus.NOT_FOUND, "The issuance does not exist", null);
    }

    @ExceptionHandler(OfferNotRenewableException.class)
    public ResponseEntity<GlobalErrorMessage> handleOfferNotRenewable(
            OfferNotRenewableException ex, ServerHttpRequest request) {
        return errors.problem(ex, request, GlobalErrorTypes.OFFER_NOT_RENEWABLE.getCode(), "Offer not renewable",
                HttpStatus.CONFLICT,
                "The issuance is no longer a draft, or its delivery mode has no credential offer", null);
    }

    @ExceptionHandler(RenewalDeliveryFailedException.class)
    public ResponseEntity<GlobalErrorMessage> handleRenewalDeliveryFailed(
            RenewalDeliveryFailedException ex, ServerHttpRequest request) {
        return errors.problem(ex, request, DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value(),
                DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.title(), HttpStatus.SERVICE_UNAVAILABLE,
                "The credential offer could not be delivered; the previous offer is still valid",
                RENEWAL_RETRY_AFTER_SECONDS);
    }
}
