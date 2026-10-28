package es.in2.issuer.backend.signing.infrastructure.onboarding.audit;

import com.eudistack.auditoria.application.AuditPublisher;
import com.eudistack.auditoria.context.AuditContextScope;
import com.eudistack.auditoria.context.AuditContexts;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditFact;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;
import es.in2.issuer.backend.signing.infrastructure.onboarding.SigningConfigurationAuditSink;

import java.sql.Connection;

/**
 * {@link SigningConfigurationAuditSink} on the outbox of the EUD-244 audit starter: the event is staged in
 * {@code public.audit_outbox}, and the dispatcher of the Issuer sends it later.
 *
 * <p>{@link #stage} runs inside the Spring transaction of the business change (the tool's data source is the
 * starter's), so the row is committed or rolled back with it; the starter refuses to stage outside a transaction.
 * The connection argument is not used for that reason. A rejected onboarding is staged by the store in a
 * transaction of its own. The tenant and the actor (the ARN of the AWS caller) come from an
 * {@link AuditContexts#system} scope opened around the call; nothing is read from configuration.
 *
 * <p>{@code details} carry exactly the fields of the catalogue for {@code SigningConfigurationChanged}
 * ({@code operation}, {@code previous_modality}, {@code new_modality}, {@code signing_certificate}); the
 * starter rejects a payload with a secret.
 */
public class OutboxSigningConfigurationAuditSink implements SigningConfigurationAuditSink {

    static final String EVENT_TYPE = "SigningConfigurationChanged";
    static final String ACTION = "ConfigureSigning";
    /** Reason of a failed retirement: a failure carries no rejection reason of its own. */
    static final String FAILURE_REASON = "OperationFailed";
    /** The module that owns the event (DT-002 §3.9.3); the process is the Issuer's, whose source is {@code issuer}. */
    static final String SOURCE = "signing";

    private final AuditPublisher publisher;

    public OutboxSigningConfigurationAuditSink(AuditPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void stage(Connection connection, SigningConfigurationChanged event) {
        try (AuditContextScope scope = AuditContexts.system(event.tenant(), event.actor(), event.correlationId())) {
            publisher.stage(draft(event));
        }
    }

    static AuditDraft draft(SigningConfigurationChanged event) {
        AuditFact fact = AuditFact.builder(EVENT_TYPE)
                .action(ACTION)
                .resource("signing-configuration:" + event.tenant())
                .source(SOURCE)
                .detail("operation", event.operation().catalogName())
                .detail("previous_modality", event.previousModality() == null ? null : modality(event.previousModality()))
                .detail("new_modality", event.newModality() == null ? null : modality(event.newModality()))
                .detail("signing_certificate", event.signingCertificateSha256() == null
                        ? null : "sha256:" + event.signingCertificateSha256())
                .build();
        return switch (event.result()) {
            case SUCCESS -> AuditDraft.success(fact);
            case DENIED -> AuditDraft.denied(fact, event.reason().catalogName());
            case FAILURE -> AuditDraft.failure(fact, event.reason() == null ? FAILURE_REASON : event.reason().catalogName());
        };
    }

    private static String modality(SigningModality modality) {
        return switch (modality) {
            case QTSP -> "Qtsp";
            case OWN_KEY -> "OwnKey";
        };
    }
}
