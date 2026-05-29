package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@ShellComponent
@Profile("key-migration")
@RequiredArgsConstructor
@Slf4j
public class KeyMigrationScript {

    private final KeyMigrationWorkflow keyMigrationWorkflow;
    private final CliOperatorAuthFilter filter;
    private final KeyMigrationProperties properties;

    @ShellMethod("Run PoC: export key from Vault and validate in DB")
    public void poc(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        keyMigrationWorkflow.executePoc(properties.legacyKeyId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, properties.tenantDomain()))
                .block();
        System.out.println("PoC completed. legacyKeyId=" + properties.legacyKeyId());
    }

    @ShellMethod("Execute production migration: mark key as MIGRATED in DB")
    public void migrate(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanA(operatorId);
        keyMigrationWorkflow.executeMigration(properties.legacyKeyId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, properties.tenantDomain()))
                .block();
        System.out.println("Migration completed. State: MIGRATED. legacyKeyId=" + properties.legacyKeyId());
    }

@ShellMethod("Roll back migration: deactivate key in DB and mark as ROLLED_BACK")
public void rollback(@ShellOption("--operator-id") String operatorId) {
    filter.validatePlanA(operatorId);
    if (properties.legacyKeyId() == null || properties.legacyKeyId().isBlank()) {
        throw new IllegalStateException("Missing required property: issuer.dome.key-migration.legacy-key-id");
    }
    keyMigrationWorkflow.executeRollback(properties.legacyKeyId())
            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, properties.tenantDomain()))
            .block();
    System.out.println("Rollback completed. State: ROLLED_BACK. legacyKeyId=" + properties.legacyKeyId());
}
}

