package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

public interface KeyMigrationAuditPort {

    Mono<Void> recordPocResult(LegacyKeyId keyId, MigrationStatus result, String evidenceUri);

    Mono<Void> recordPlanAOk(LegacyKeyId keyId, KmsAlias alias, String evidenceUri);

    Mono<Void> recordPlanBReissue(UUID batchId, int ok, int skipped, int failed);

    Mono<Void> recordFailure(LegacyKeyId keyId, Throwable cause);

    void emitCloudWatchAudit(String event, Map<String, Object> details);
}
