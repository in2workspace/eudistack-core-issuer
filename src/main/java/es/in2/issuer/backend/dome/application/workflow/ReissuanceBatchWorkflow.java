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
import es.in2.issuer.backend.shared.domain.util.JsonCanonicalizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

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
    private final ObjectMapper objectMapper;

    public record BatchSummary(int ok, int skipped, int failed) {}

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


    private Mono<Void> processCredential(Issuance issuance,
                                          AtomicInteger ok,
                                          AtomicInteger skipped,
                                          AtomicInteger failed) {
        if (issuance.getValidUntil() != null
                && issuance.getValidUntil().toInstant().isBefore(Instant.now())) {
            log.debug("skipping expired issuanceId={}", issuance.getIssuanceId());
            skipped.incrementAndGet();
            return Mono.empty();
        }
        if (issuance.getCredentialStatus() == CredentialStatusEnum.REVOKED) {
            log.debug("skipping revoked issuanceId={}", issuance.getIssuanceId());
            skipped.incrementAndGet();
            return Mono.empty();
        }

        return auditRepo.findOkBySourceRecordId(issuance.getIssuanceId())
                .map(existing -> true)
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
        String holderCnfJwk = extractCnfJwkFromSignedCredential(issuance.getSignedCredential());

        ReissuanceContext context = new ReissuanceContext(
                issuance.getIssuanceId(), holderCnfJwk, validFrom, validUntil);

        return issueWorkflow.reissue(context)
                .flatMap(signedCredential -> {
                    String sourceHash = JsonCanonicalizer.sha256(issuance.getCredentialDataSet());
                    String targetHash = JsonCanonicalizer.sha256(signedCredential);

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

    private String extractCnfJwkFromSignedCredential(String signedCredential) {
        if (signedCredential == null || signedCredential.isBlank()) {
            return "";
        }
        try {
            // SD-JWT uses '~' as separator — keep only the JWT portion
            String jwt = signedCredential.contains("~")
                    ? signedCredential.split("~")[0]
                    : signedCredential;

            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return "";
            }

            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            Map<?, ?> payload = objectMapper.readValue(payloadBytes, Map.class);

            Object cnf = payload.get("cnf");
            if (cnf instanceof Map<?, ?> cnfMap) {
                Object jwk = cnfMap.get("jwk");
                if (jwk != null) {
                    return objectMapper.writeValueAsString(jwk);
                }
            }
            return "";
        } catch (Exception e) {
            log.warn("extractCnfJwkFromSignedCredential: could not parse cnf.jwk, proceeding without holder binding: {}",
                    e.getMessage());
            return "";
        }
    }
}

