package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Where the audit events of the onboarding tool go. The shape is the one of a transactional outbox: the
 * event is staged on the connection of the business transaction, so it exists if and only if the change
 * does, and it is published after the commit.
 *
 * <p>Today the implementation is {@link LoggingSigningConfigurationAuditSink}, which writes a structured
 * line. When the outbox of EUD-244 (public.audit_outbox) is available, its implementation inserts the row in
 * {@link #stage} on the same connection (or hands the event to the EUD-244 starter) and
 * {@link #afterCommit} does nothing; the rest of the tool does not change.
 */
public interface SigningConfigurationAuditSink {

    /**
     * Called inside the transaction of {@code connection}, which is not committed yet. An exception makes the
     * whole transaction roll back.
     */
    void stage(Connection connection, SigningConfigurationChanged event) throws SQLException;

    /** Called once the transaction that staged the event committed. It must not throw. */
    default void afterCommit(SigningConfigurationChanged event) {
        // Nothing to do by default: an outbox is drained by its dispatcher, not by this call.
    }
}
