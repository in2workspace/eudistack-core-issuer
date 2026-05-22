package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

/**
 * Spring Shell commands for Plan-A DOME key migration.
 * <p>
 * ES-01: {@code System.out} is acceptable here — it is the sole place in the project
 * where direct console output to the operator is legitimate.
 * </p>
 */
@Slf4j
@ShellComponent
@Profile("key-migration")
@RequiredArgsConstructor
public class KeyMigrationScript {

    private final KeyMigrationWorkflow keyMigrationWorkflow;
    private final CliOperatorAuthFilter filter;
    private final KeyMigrationProperties properties;
    private final KmsImportPort kmsImportPort;

    /**
     * Runs Plan-A Proof-of-Concept validation: imports the legacy key into KMS
     * and exercises it with a test signature. Transitions status to POC_OK on success.
     */
    @ShellMethod("Run Plan-A Proof of Concept")
    public void poc(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        keyMigrationWorkflow.executePoc(properties.legacyKeyId()).block();
        // ES-01: direct operator feedback via System.out — acceptable in @ShellMethod only
        System.out.println("PoC completed successfully. alias=" + properties.kmsAlias()
                + " legacyKeyId=" + properties.legacyKeyId());
    }

    /**
     * Runs Plan-A production import: full migration pipeline.
     * Transitions status to PLAN_A_OK on success.
     */
    @ShellMethod("Run Plan-A production import")
    public void production(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        keyMigrationWorkflow.executeProduction(properties.legacyKeyId()).block();
        // ES-01: direct operator feedback via System.out — acceptable in @ShellMethod only
        System.out.println("Production import completed. alias=" + properties.kmsAlias()
                + " legacyKeyId=" + properties.legacyKeyId());
    }

    /**
     * EC-03: Deletes the imported key material from KMS, leaving key metadata intact
     * but rendering the key non-functional. This is the rollback path.
     */
    @ShellMethod("Delete imported key material (EC-03)")
    public void rollback(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        String maskedOperator = operatorId.substring(0, Math.min(4, operatorId.length())) + "****";
        log.warn("rollback: deleting imported key material alias={} operatorId={}",
                properties.kmsAlias(), maskedOperator);
        kmsImportPort.deleteImportedKeyMaterial(new KmsAlias(properties.kmsAlias())).block();
        // ES-01: direct operator feedback via System.out — acceptable in @ShellMethod only
        System.out.println("Rollback complete: key material deleted for alias=" + properties.kmsAlias());
    }
}

