package es.in2.issuer.backend.issuance.domain.exception;

public class DeliveryModeNotEligibleException extends RuntimeException {
    public DeliveryModeNotEligibleException(String message) {
        super(message);
    }
}