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

@Slf4j
@ShellComponent
@Profile("key-migration")
@RequiredArgsConstructor
public class KeyMigrationScript {

    private final KeyMigrationWorkflow keyMigrationWorkflow;
    private final CliOperatorAuthFilter filter;
    private final KeyMigrationProperties properties;
    private final KmsImportPort kmsImportPort;

    @ShellMethod("Run Plan-A Proof of Concept")
    public void poc(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        keyMigrationWorkflow.executePoc(properties.legacyKeyId()).block();
        System.out.println("PoC completed successfully. alias=" + properties.kmsAlias()
                + " legacyKeyId=" + properties.legacyKeyId());
    }

    @ShellMethod("Run Plan-A production import")
    public void production(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        keyMigrationWorkflow.executeProduction(properties.legacyKeyId()).block();
        System.out.println("Production import completed. alias=" + properties.kmsAlias()
                + " legacyKeyId=" + properties.legacyKeyId());
    }

    @ShellMethod("Delete imported key material (EC-03)")
    public void rollback(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        String maskedOperator = operatorId.substring(0, Math.min(4, operatorId.length())) + "****";
        log.warn("rollback: deleting imported key material alias={} operatorId={}",
                properties.kmsAlias(), maskedOperator);
        kmsImportPort.deleteImportedKeyMaterial(new KmsAlias(properties.kmsAlias())).block();
        System.out.println("Rollback complete: key material deleted for alias=" + properties.kmsAlias());
    }
}
