package es.in2.issuer.backend.shared.domain.exception;

public class TenantMismatchException extends RuntimeException {

    public TenantMismatchException(String message) {
        super(message);
    }
}
