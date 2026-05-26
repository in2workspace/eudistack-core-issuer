package es.in2.issuer.backend.dome.infrastructure.adapter.audit;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.KeyMigrationAuditPort;
import es.in2.issuer.backend.dome.infrastructure.adapter.persistence.R2dbcMigrationAuditRepository;
import es.in2.issuer.backend.dome.infrastructure.observability.KeyMigrationAuditLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Primary
@Component
@RequiredArgsConstructor
public class CloudWatchKeyMigrationAuditAdapter implements KeyMigrationAuditPort {

    private static final Set<String> FORBIDDEN_DETAIL_KEYS =
            Set.of("ciphertext", "privateKey", "keyMaterial");

    private final R2dbcMigrationAuditRepository auditRepository;
    private final KeyMigrationAuditLogger auditLogger;

    @Override
    public Mono<Void> recordPocResult(LegacyKeyId keyId, MigrationStatus result, String evidenceUri) {
        MigrationAuditEntry entry = MigrationAuditEntry.builder()
                .sourceHash(keyId.value())
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome("POC_RESULT:" + result.name())
                .errorMessage(evidenceUri)
                .build();
        return auditRepository.save(entry)
                .doOnSuccess(saved -> auditLogger.logPocResult(keyId, result))
                .then();
    }

    @Override
    public Mono<Void> recordPlanAOk(LegacyKeyId keyId, KmsAlias alias, String evidenceUri) {
        MigrationAuditEntry entry = MigrationAuditEntry.builder()
                .sourceHash(keyId.value())
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome("PLAN_A_OK")
                .errorMessage(evidenceUri)
                .build();
        return auditRepository.save(entry)
                .doOnSuccess(saved -> auditLogger.logPlanAOk(keyId, alias))
                .then();
    }

    @Override
    public Mono<Void> recordPlanBReissue(UUID batchId, int ok, int skipped, int failed) {
        String summary = "batchId=" + batchId + " ok=" + ok
                + " skipped=" + skipped + " failed=" + failed;
        MigrationAuditEntry entry = MigrationAuditEntry.builder()
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome("PLAN_B_REISSUE")
                .errorMessage(summary)
                .build();
        return auditRepository.save(entry)
                .doOnSuccess(saved -> auditLogger.logEvent("PLAN_B_REISSUE", summary))
                .then();
    }

    @Override
    public Mono<Void> recordFailure(LegacyKeyId keyId, Throwable cause) {
        // NFR-07: persist the full message to DB for debugging, but only log the class name.
        String errorClass = cause.getClass().getSimpleName();
        MigrationAuditEntry entry = MigrationAuditEntry.builder()
                .sourceHash(keyId.value())
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome("FAILED")
                .errorMessage(cause.getMessage())
                .build();
        return auditRepository.save(entry)
                .doOnSuccess(saved -> auditLogger.logFailure(keyId, errorClass))
                .then();
    }

    @Override
    public void emitCloudWatchAudit(String event, Map<String, Object> details) {
        validateDetails(details);
        try {
            String safeDetail = details == null ? "" : details.toString();
            auditLogger.logEvent(event, safeDetail);
        } catch (Exception ex) {
            log.error("emitCloudWatchAudit failed for event={}: {}", event, ex.getClass().getSimpleName());
        }
    }


    private void validateDetails(Map<String, Object> details) {
        if (details == null) {
            return;
        }
        for (String forbidden : FORBIDDEN_DETAIL_KEYS) {
            if (details.containsKey(forbidden)) {
                throw new IllegalArgumentException(
                        "details map must not contain sensitive key: " + forbidden);
            }
        }
    }
}
