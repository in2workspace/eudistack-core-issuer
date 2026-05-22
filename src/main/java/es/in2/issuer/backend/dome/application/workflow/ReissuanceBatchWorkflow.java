package es.in2.issuer.backend.dome.application.workflow;

import es.in2.issuer.backend.dome.application.service.KeyMigrationStateService;
import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.exception.HashMismatchException;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.model.keymigration.ReissuanceContext;
import es.in2.issuer.backend.dome.domain.spi.KeyMigrationAuditPort;
import es.in2.issuer.backend.dome.infrastructure.adapter.persistence.R2dbcMigrationAuditRepository;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Orchestrates Plan-B DOME key migration: re-issues all active credentials
 * signed with the legacy key, using the new KMS v2 alias.
 *
 * <p>ES-08: per-credential errors are absorbed (logged + counted) — the batch
 * continues. {@code onErrorResume} is used per element; {@code onErrorContinue}
 * is intentionally avoided (WebFlux anti-pattern).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ReissuanceBatchWorkflow {

    private final IssuanceRepository issuanceRepository;
    private final R2dbcMigrationAuditRepository auditRepo;
    private final KeyMigrationAuditPort auditPort;
    private final KeyMigrationStateService stateService;
    private final KeyMigrationProperties properties;
    private final IssueSignedCredentialWorkflow issueWorkflow;

    /**
     * Summary of a completed re-issuance batch run.
     *
     * @param ok      credentials successfully re-issued and audit-recorded.
     * @param skipped credentials skipped (already done, expired, or revoked).
     * @param failed  credentials that produced an error during re-issuance.
     */
    public record BatchSummary(int ok, int skipped, int failed) {}

    /**
     * Executes the Plan-B batch re-issuance for the given legacy key ID.
     *
     * @throws ConflictingMigrationStateException (ES-04) if the record is already {@code PLAN_A_OK}.
     */
    public Mono<BatchSummary> execute(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);
        UUID batchId = UUID.randomUUID();
        AtomicInteger ok = new AtomicInteger(0);
        AtomicInteger skipped = new AtomicInteger(0);
        AtomicInteger failed = new AtomicInteger(0);

        log.info("execute: starting Plan-B batch batchId={} legacyKeyId={}", batchId, legacyKeyId.value());

        Mono<Void> preFlight = stateService.currentStatus(legacyKeyIdStr)
                .flatMap(status -> {
                    if (status == MigrationStatus.PLAN_A_OK) {
                        return Mono.error(new ConflictingMigrationStateException(
                                legacyKeyId.value() + " is already PLAN_A_OK (ES-04)"));
                    }
                    return Mono.empty();
                });

        return preFlight
                .thenMany(issuanceRepository.findAllOrderByUpdatedDesc())
                .flatMap(issuance -> processCredential(issuance, ok, skipped, failed), 1)
                .then(Mono.defer(() -> {
                    log.info("execute: batch complete batchId={} ok={} skipped={} failed={}",
                            batchId, ok.get(), skipped.get(), failed.get());
                    return auditPort.recordPlanBReissue(batchId, ok.get(), skipped.get(), failed.get());
                }))
                .then(Mono.fromCallable(() -> new BatchSummary(ok.get(), skipped.get(), failed.get())));
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    private Mono<Void> processCredential(Issuance issuance,
                                          AtomicInteger ok,
                                          AtomicInteger skipped,
                                          AtomicInteger failed) {
        // EC-05: skip if already expired
        if (issuance.getValidUntil() != null
                && issuance.getValidUntil().toInstant().isBefore(Instant.now())) {
            log.debug("skipping expired issuanceId={}", issuance.getIssuanceId());
            skipped.incrementAndGet();
            return Mono.empty();
        }
        // EC-06: skip if revoked
        if (issuance.getCredentialStatus() == CredentialStatusEnum.REVOKED) {
            log.debug("skipping revoked issuanceId={}", issuance.getIssuanceId());
            skipped.incrementAndGet();
            return Mono.empty();
        }

        return auditRepo.findBySourceRecordId(issuance.getIssuanceId())
                .map(existing -> "OK".equals(existing.getOutcome()))
                .defaultIfEmpty(false)
                .flatMap(alreadyOk -> {
                    if (alreadyOk) {
                        log.debug("skipping already-migrated issuanceId={}", issuance.getIssuanceId());
                        skipped.incrementAndGet();
                        return Mono.<Void>empty();
                    }
                    return doReissue(issuance, ok);
                })
                .onErrorResume(ex -> {
                    // ES-08: absorb per-credential errors — never propagate
                    log.error("reissuance failed for issuanceId={}: {}", issuance.getIssuanceId(), ex.getMessage());
                    failed.incrementAndGet();
                    return Mono.empty();
                });
    }

    private Mono<Void> doReissue(Issuance issuance, AtomicInteger ok) {
        Instant validFrom = issuance.getValidFrom() != null
                ? issuance.getValidFrom().toInstant() : Instant.now();
        Instant validUntil = issuance.getValidUntil() != null
                ? issuance.getValidUntil().toInstant() : null;
        String holderCnfJwk = issuance.getSubject() != null ? issuance.getSubject() : "";

        ReissuanceContext context = new ReissuanceContext(
                issuance.getIssuanceId(), holderCnfJwk, validFrom, validUntil);

        return issueWorkflow.reissue(context)
                .flatMap(signedCredential -> {
                    String sourceHash = sha256(issuance.getCredentialDataSet());
                    String targetHash = sha256(signedCredential);

                    // ES-09: detect hash computation failure (defensive)
                    if (targetHash == null || targetHash.isBlank()) {
                        return Mono.error(new HashMismatchException(
                                "targetHash is blank for issuanceId=" + issuance.getIssuanceId()));
                    }

                    MigrationAuditEntry entry = MigrationAuditEntry.builder()
                            .sourceRecordId(issuance.getIssuanceId())
                            .sourceHash(sourceHash)
                            .targetHash(targetHash)
                            .migratedAt(Instant.now())
                            .replayAttempt(0)
                            .outcome("OK")
                            .build();

                    return auditRepo.save(entry)
                            .doOnSuccess(saved -> {
                                ok.incrementAndGet();
                                log.debug("reissued issuanceId={}", issuance.getIssuanceId());
                            })
                            .then();
                });
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input != null
                    ? input.getBytes(StandardCharsets.UTF_8) : new byte[0]);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}

