package es.in2.issuer.backend.signing.infrastructure.onboarding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;

/**
 * Temporary {@link SigningConfigurationAuditSink}: the outbox of EUD-244 does not exist yet, so the event
 * is written as one JSON line to the dedicated audit logger, after the transaction commits (a line for a
 * change that was rolled back would be false). Field names follow the EUD-244 catalogue
 * ({@code SigningConfigurationChanged}, action {@code ConfigureSigning}).
 *
 * <p>Nothing secret is written: the event holds no key reference, no certificate and no key material.
 */
public class LoggingSigningConfigurationAuditSink implements SigningConfigurationAuditSink {

    /** Logger name an operator can route to the audit trail. */
    public static final String AUDIT_LOGGER = "es.in2.issuer.backend.signing.onboarding.audit";

    private static final Logger AUDIT = LoggerFactory.getLogger(AUDIT_LOGGER);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void stage(Connection connection, SigningConfigurationChanged event) {
        // The line is written after the commit; there is nothing to stage in the database yet.
    }

    /** A failure to write the line is logged by the caller, as for any sink. */
    @Override
    public void afterCommit(SigningConfigurationChanged event) {
        AUDIT.info(toJson(event));
    }

    static String toJson(SigningConfigurationChanged event) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("type", "SigningConfigurationChanged");
        root.put("action", "ConfigureSigning");
        root.put("tenant", event.tenant());
        root.put("result", event.result().catalogName());
        if (event.reason() != null) {
            root.put("reason", event.reason().catalogName());
        }
        root.put("actor", event.actor());
        root.put("duration_ms", event.duration().toMillis());
        root.put("occurred_at", event.occurredAt().toString());
        if (event.correlationId() != null) {
            root.put("correlation_id", event.correlationId());
        }
        ObjectNode details = root.putObject("details");
        details.put("operation", event.operation().catalogName());
        if (event.previousModality() != null) {
            details.put("previous_modality", modality(event.previousModality()));
        }
        if (event.newModality() != null) {
            details.put("new_modality", modality(event.newModality()));
        }
        if (event.signingCertificateSha256() != null) {
            details.put("signing_certificate", event.signingCertificateSha256());
        }
        try {
            return MAPPER.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The audit event cannot be serialised", e);
        }
    }

    private static String modality(SigningModality modality) {
        return switch (modality) {
            case QTSP -> "Qtsp";
            case OWN_KEY -> "OwnKey";
        };
    }
}
