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
                // Timeout and PostImportValidationFailedException mapping are handled
                // centrally in AwsKmsImportAdapter.sign(). No second timeout here to
                // avoid duplicate handling and inconsistent error messages (ES-07).
                .flatMap(sig -> {
                    if (sig == null || sig.isBlank()) {
                        return Mono.error(new PostImportValidationFailedException("KMS returned empty signature"));
                    }
                    log.debug("importAndValidate: signature obtained successfully");
                    return Mono.just(sig);
                });
    }

    private Mono<Void> failClosed(LegacyKeyId legacyKeyId, Throwable ex) {
        log.error("key migration failed for legacyKeyId={}: errorClass={}",
                legacyKeyId.value(), ex.getClass().getSimpleName());
        return stateService.transitionTo(legacyKeyId, MigrationStatus.FAILED)
                .then(auditPort.recordFailure(legacyKeyId, ex))
                .then(Mono.error(ex));
    }

    private boolean isImportTokenExpiry(Throwable e) {
        String name = e.getClass().getSimpleName();
        return name.contains("ExpiredImportToken") || name.contains("InvalidImportToken");
    }
}


