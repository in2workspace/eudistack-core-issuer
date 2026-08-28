package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
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
@Order(2)
public class IssuanceExceptionHandler {

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

    /**
     * Nothing usable was delivered (EUD-33 AC-06): either {@code direct} was declared and failed
     * -- ES-02 forbids a 2xx there, a wallet dispatch does not compensate for not returning the
     * credential the caller asked for -- or no declared mode succeeded at all.
     *
     * <p>A single 500 rather than a status taxonomy by cause: no AC asks for one, and the actionable
     * part is the per-mode outcome in {@code delivery_results}, which travels in the body either way.
     */
    @ExceptionHandler(DeliveryFailedException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleDeliveryFailed(
            DeliveryFailedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWithDelivery(
                ex, request,
                GlobalErrorTypes.DELIVERY_FAILED.getCode(),
                "Delivery failed",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "No declared delivery mode completed successfully",
                ex.deliveryResults(),
                ex.credentialOfferUri()
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
                "The holder key is missing or malformed (expected exactly one of jwk/kid/x5c)"
        );
    }
}
