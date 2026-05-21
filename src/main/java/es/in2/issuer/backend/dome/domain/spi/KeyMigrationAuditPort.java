package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

public interface KeyMigrationAuditPort {

    /**
     * Records the outcome of the Proof-of-Concept signing test for a given key.
     */
    Mono<Void> recordPocResult(LegacyKeyId keyId, MigrationStatus result, String evidenceUri);

    /**
     * Records a successful Plan-A (in-place key import) for a given key.
     */
    Mono<Void> recordPlanAOk(LegacyKeyId keyId, KmsAlias alias, String evidenceUri);

    /**
     * Records the aggregate outcome of a Plan-B re-issuance batch.
     */
    Mono<Void> recordPlanBReissue(UUID batchId, int ok, int skipped, int failed);

    /**
     * Records a terminal failure for a given key migration.
     */
    Mono<Void> recordFailure(LegacyKeyId keyId, String errorMessage);

    /**
     * Emits a structured CloudWatch audit event. This method is intentionally synchronous
     * (fire-and-forget) so it can be called from Reactor side-effects (e.g. {@code doOnNext}).
     */
    void emitCloudWatchAudit(String event, Map<String, Object> details);
}

