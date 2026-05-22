package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.application.workflow.ReissuanceBatchWorkflow;
import es.in2.issuer.backend.dome.application.workflow.ReissuanceBatchWorkflow.BatchSummary;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

/**
 * Spring Shell commands for Plan-B DOME credential re-issuance batch.
 * <p>
 * ES-01: {@code System.out} is acceptable here — it is the sole place in the project
 * where direct console output to the operator is legitimate.
 * </p>
 */
@Slf4j
@ShellComponent
@Profile("key-migration")
@RequiredArgsConstructor
public class ReissuanceBatchScript {

    private final ReissuanceBatchWorkflow reissuanceBatchWorkflow;
    private final CliOperatorAuthFilter filter;
    private final KeyMigrationProperties properties;

    /**
     * Runs Plan-B re-issuance batch: re-issues all active credentials previously
     * signed with the legacy key, using the new KMS v2 alias.
     */
    @ShellMethod("Run Plan-B re-issuance batch")
    public void reissuanceBatch(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanB(operatorId);
        BatchSummary result = reissuanceBatchWorkflow.execute(properties.legacyKeyId()).block();
        if (result != null) {
            // ES-01: direct operator feedback via System.out — acceptable in @ShellMethod only
            System.out.printf("Batch complete: ok=%d skipped=%d failed=%d%n",
                    result.ok(), result.skipped(), result.failed());
        }
    }
}

