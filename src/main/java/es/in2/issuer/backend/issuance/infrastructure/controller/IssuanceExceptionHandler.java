package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalTenantMismatchException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
@Order(2)
public class IssuanceExceptionHandler {

    /** Seconds a client waits before retrying a renewal whose delivery failed. */
    private static final int RENEWAL_RETRY_AFTER_SECONDS = 30;

    private final ErrorResponseFactory errors;

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

    @ExceptionHandler(InvalidDeliveryModeException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidDeliveryMode(
            InvalidDeliveryModeException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_REQUEST.getCode(),
                "Invalid request",
                HttpStatus.BAD_REQUEST,
                "The delivery mode is missing, blank or unknown"
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
                "The holder key is missing or malformed (expected a jwk member with an EC P-256 public key)"
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
