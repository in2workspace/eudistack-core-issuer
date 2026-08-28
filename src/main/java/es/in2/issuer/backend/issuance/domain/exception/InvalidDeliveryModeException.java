package es.in2.issuer.backend.issuance.domain.exception;

public class InvalidDeliveryModeException extends RuntimeException {
    public InvalidDeliveryModeException(String message) {
        super(message);
    }
}