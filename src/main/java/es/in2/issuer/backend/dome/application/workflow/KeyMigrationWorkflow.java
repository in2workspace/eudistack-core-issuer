package es.in2.issuer.backend.dome.application.workflow;

import es.in2.issuer.backend.dome.application.service.KeyMigrationStateService;
import es.in2.issuer.backend.dome.domain.exception.PostImportValidationFailedException;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.KeyMigrationAuditPort;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

/**
 * Orchestrates Plan-A DOME key migration:
 * Vault export → KMS import → post-import PoC validation → PLAN_A_OK transition.
 * <p>
 * AC-08 fail-closed: any error in the pipeline transitions the record to {@code FAILED}
 * and re-throws the original exception so the caller can decide on retry/escalation.
 * </p>
 * <p>
 * {@code @Lazy}: this service is only invoked from the migration CLI runner.
 * Deferring initialization avoids the KMS client region check at application startup
 * in environments without AWS credentials (e.g. local development / test).
 * </p>
 */
@Slf4j
@Lazy
@Service
@RequiredArgsConstructor
public class KeyMigrationWorkflow {

    private static final byte[] POC_TEST_DATA = "dome-poc-test".getBytes();

    private final KmsImportPort kmsImportPort;
    private final VaultExportPort vaultExportPort;
    private final KeyMigrationAuditPort auditPort;
    private final KeyMigrationStateService stateService;
    private final KeyMigrationProperties properties;

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Executes the Proof-of-Concept validation: imports the legacy key material into KMS
     * and verifies the key is functional by requesting a test signature.
     * Transitions status to {@code POC_OK} on success, {@code FAILED} on error.
     */
    public Mono<Void> executePoc(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);
        KmsAlias alias = new KmsAlias(properties.kmsAlias());
        log.info("executePoc: starting for legacyKeyId={}", legacyKeyId.value());

        return importAndValidate(legacyKeyId, alias)
                .flatMap(signature ->
                        stateService.transitionTo(legacyKeyId, MigrationStatus.POC_OK)
                                .then(auditPort.recordPocResult(legacyKeyId, MigrationStatus.POC_OK, "poc-validated")))
                .onErrorResume(ex -> failClosed(legacyKeyId, ex));
    }

    /**
     * Executes the production import: same pipeline as PoC but transitions to
     * {@code PLAN_A_OK} on success, recording the evidence in the audit trail.
     */
    public Mono<Void> executeProduction(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);
        KmsAlias alias = new KmsAlias(properties.kmsAlias());
        log.info("executeProduction: starting for legacyKeyId={}", legacyKeyId.value());

        return importAndValidate(legacyKeyId, alias)
                .flatMap(signature ->
                        stateService.transitionTo(legacyKeyId, MigrationStatus.PLAN_A_OK)
                                .then(auditPort.recordPlanAOk(legacyKeyId, alias, "plan-a-production")))
                .onErrorResume(ex -> failClosed(legacyKeyId, ex));
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /**
     * Core import + validation pipeline shared by PoC and production runs.
     *
     * @return the base64-encoded PoC signature produced by KMS (non-blank).
     */
    private Mono<String> importAndValidate(LegacyKeyId legacyKeyId, KmsAlias alias) {
        return kmsImportPort.describeKey(alias)   // ES-02: throws KmsAliasNotProvisionedException if absent
                .flatMap(ignored -> kmsImportPort.getParametersForImport(alias))
                .flatMap(params ->
                        vaultExportPort.exportWrapped(legacyKeyId, params.publicKeyPem())
                        .flatMap(envelope ->
                                Mono.defer(() -> kmsImportPort.importKeyMaterial(alias, envelope, params))
                                        .retryWhen(Retry.max(3).filter(this::isImportTokenExpiry))
                                )
                )
                .then(Mono.defer(() -> kmsImportPort.sign(alias, POC_TEST_DATA)))
                .timeout(Duration.ofSeconds(10))
                .onErrorMap(TimeoutException.class,
                        e -> new PostImportValidationFailedException("sign timeout exceeded 10s", e))
                .flatMap(sig -> {
                    if (sig == null || sig.isBlank()) {
                        return Mono.error(new PostImportValidationFailedException("KMS returned empty signature"));
                    }
                    log.debug("importAndValidate: signature obtained successfully");
                    return Mono.just(sig);
                });
    }

    /**
     * AC-08 fail-closed: transitions status to {@code FAILED}, records the
     * failure in the audit trail, then re-throws the original exception.
     */
    private Mono<Void> failClosed(LegacyKeyId legacyKeyId, Throwable ex) {
        log.error("key migration failed for legacyKeyId={}: {}", legacyKeyId.value(), ex.getMessage());
        return stateService.transitionTo(legacyKeyId, MigrationStatus.FAILED)
                .then(auditPort.recordFailure(legacyKeyId, ex.getMessage()))
                .then(Mono.error(ex));
    }

    /**
     * Detects KMS import-token expiry exceptions by class name (ES-retry guard).
     */
    private boolean isImportTokenExpiry(Throwable e) {
        String name = e.getClass().getSimpleName();
        return name.contains("ExpiredImportToken") || name.contains("InvalidImportToken");
    }
}


