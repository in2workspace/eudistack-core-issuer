package es.in2.issuer.backend.signing.infrastructure.onboarding;

import javax.sql.DataSource;

/**
 * Builds the outbox {@link SigningConfigurationAuditSink}. It is loaded by class name, so the main code has no
 * reference to the audit starter: the implementation lives in the opt-in source set that is only compiled with
 * {@code -PauditStarter}.
 */
public interface AuditSinkFactory {

    /**
     * @param dataSource the data source of the tool; the sink must stage on it, so that it joins the transaction
     *                   of the business change
     */
    AuditSinkHandle open(DataSource dataSource);
}
