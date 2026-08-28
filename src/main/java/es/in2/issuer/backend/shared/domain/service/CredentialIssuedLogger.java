package es.in2.issuer.backend.shared.domain.service;

/**
 * Business-event logging for credential issuance outcomes.
 */
public interface CredentialIssuedLogger {

    void logIssued(String configurationId);

    void logFailed(String configurationId, Throwable error);
}
