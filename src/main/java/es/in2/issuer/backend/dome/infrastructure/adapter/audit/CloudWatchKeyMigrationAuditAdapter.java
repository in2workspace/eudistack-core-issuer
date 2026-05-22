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

/**
 * CloudWatch-backed implementation of {@link KeyMigrationAuditPort}.
 * <p>
 * Persists each audit event to the {@code migration_audit} table via
 * {@link R2dbcMigrationAuditRepository}, and additionally emits structured
 * log entries tagged with {@code AUDIT_KEY_MIGRATION} via {@link KeyMigrationAuditLogger}.
 * </p>
 * <p>
 * NFR-07: the {@code details} map passed to {@link #emitCloudWatchAudit} is validated
 * against a strict deny-list of keys that could carry cryptographic material.
 * </p>
 */
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
    public Mono<Void> recordFailure(LegacyKeyId keyId, String errorMessage) {
        MigrationAuditEntry entry = MigrationAuditEntry.builder()
                .sourceHash(keyId.value())
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome("FAILED")
                .errorMessage(errorMessage)
                .build();
        return auditRepository.save(entry)
                .doOnSuccess(saved -> auditLogger.logFailure(keyId, errorMessage))
                .then();
    }

    /**
     * Fire-and-forget. Validates the details map against FORBIDDEN_DETAIL_KEYS,
     * then emits a structured audit log via {@link KeyMigrationAuditLogger}.
     * Any exception from the logger is caught and re-logged via SLF4J without propagation.
     *
     * @throws IllegalArgumentException if {@code details} contains a forbidden key
     */
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

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

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
