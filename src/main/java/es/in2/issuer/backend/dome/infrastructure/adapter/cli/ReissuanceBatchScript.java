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

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@ShellComponent
@Profile("key-migration")
@RequiredArgsConstructor
public class ReissuanceBatchScript {

    private final ReissuanceBatchWorkflow reissuanceBatchWorkflow;
    private final CliOperatorAuthFilter filter;
    private final KeyMigrationProperties properties;

    @ShellMethod("Run Plan-B re-issuance batch")
    public void reissuanceBatch(@ShellOption("--operator-id") String operatorId) {
        filter.validatePlanB(operatorId);
        BatchSummary result = reissuanceBatchWorkflow.execute(properties.legacyKeyId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, properties.tenantDomain()))
                .block();
        if (result != null) {
            System.out.printf("Batch complete: ok=%d skipped=%d failed=%d%n",
                    result.ok(), result.skipped(), result.failed());
        }
    }
}
