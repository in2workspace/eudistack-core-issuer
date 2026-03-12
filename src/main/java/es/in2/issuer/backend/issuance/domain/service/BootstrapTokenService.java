package es.in2.issuer.backend.issuance.domain.service;

public interface BootstrapTokenService {

    /**
     * Returns the current bootstrap token, or null if already consumed.
     */
    String getToken();

    /**
     * Atomically validates and consumes the token. Returns true only once
     * for the correct token; all subsequent calls return false.
     */
    boolean consumeIfValid(String token);
}
