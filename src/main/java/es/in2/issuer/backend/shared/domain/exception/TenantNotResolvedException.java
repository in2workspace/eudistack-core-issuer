package es.in2.issuer.backend.shared.domain.exception;

public class TenantNotResolvedException extends RuntimeException {

    public TenantNotResolvedException(String message) {
        super(message);
    }
}
