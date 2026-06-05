package es.in2.issuer.backend.dome.application.workflow;

import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.IdempotencyCachePort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsAuditLogger;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsMetrics;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Application workflow orchestrating the credential synchronization process.
 * It handles tenant validation, cache checking for idempotency, database fetching,
 * timeout handling, and observability (metrics and audit logging).
 */
@Service
public class ResyncCredentialsWorkflow {

    private final TenantConfigPort tenantConfigPort;
    private final IdempotencyCachePort idempotencyCachePort;
    private final CredentialSyncPort credentialSyncPort;

    private final SyncCredentialsMetrics metrics;
    private final SyncCredentialsAuditLogger auditLogger;

    public ResyncCredentialsWorkflow(TenantConfigPort tenantConfigPort,
                                     IdempotencyCachePort idempotencyCachePort,
                                     CredentialSyncPort credentialSyncPort,
                                     SyncCredentialsMetrics metrics,
                                     SyncCredentialsAuditLogger auditLogger) {
        this.tenantConfigPort = tenantConfigPort;
        this.idempotencyCachePort = idempotencyCachePort;
        this.credentialSyncPort = credentialSyncPort;
        this.metrics =  metrics;
        this.auditLogger = auditLogger;
    }

    /**
     * Executes the credential synchronization workflow.
     *
     * @param tenant         The identifier of the requested tenant.
     * @param idempotencyKey The unique identifier for the current sync request.
     * @param thumbprint     The cryptographic thumbprint identifying the user's wallet.
     * @return A Mono emitting the result of the workflow, including the credentials and cache status.
     */
    public Mono<ResyncWorkflowResult> execute(String tenant, IdempotencyKey idempotencyKey, HolderKeyThumbprint thumbprint) {
        IdempotencyCacheKey cacheKey = new IdempotencyCacheKey(tenant, idempotencyKey, thumbprint);
        long startTime = System.currentTimeMillis();

        return tenantConfigPort.requireConfig(tenant)
                .then(idempotencyCachePort.get(cacheKey))
                .flatMap(optionalChacheResult -> {
                    if (optionalChacheResult.isPresent()) {
                        auditLogger.logSyncEvent(tenant, idempotencyKey.value().toString(), "SUCCESS_CACHE_HIT");
                        metrics.recordRecoveryAttempt(tenant, "SUCCESS", "CACHE_HIT", true, "RECOVERY");

                        return Mono.just(new ResyncWorkflowResult(optionalChacheResult.get(), true));
                    }
                    else {
                        return credentialSyncPort.findByHolderKey(tenant, thumbprint)
                                .collectList()
                                .timeout(Duration.ofSeconds(5))
                                .map(credentialsList -> new SyncCredentialsResult(credentialsList))
                                .flatMap(newResult -> idempotencyCachePort.put(cacheKey, newResult)
                                        .then(Mono.fromRunnable(() -> {
                                            auditLogger.logSyncEvent(tenant, idempotencyKey.value().toString(), "SUCCESS_DB_FETCH");
                                            metrics.recordRecoveryAttempt(tenant, "SUCCESS", "DB_FETCH", false, "RECOVERY");
                                        }))
                                        .thenReturn(new ResyncWorkflowResult(newResult, false)));

                    }
                })
                .doOnError(error -> {
                    String reason = error.getClass().getSimpleName();
                    auditLogger.logSyncEvent(tenant, idempotencyKey.value().toString(), "ERROR_" + reason);
                    metrics.recordRecoveryAttempt(tenant, "ERROR", reason, false, "RECOVERY");
                })
                .doFinally(signalType -> {
                    Duration duration = Duration.ofMillis(System.currentTimeMillis() - startTime);
                    metrics.recordRecoveryDuration(duration);
                });
    }

    /**
     * Record holding the result of the synchronization workflow.
     * @param syncCredentialsResult The credentials retrieved (from cache or DB).
     * @param isCacheHit            Flag indicating if the response was served from cache.
     */
    public record ResyncWorkflowResult(
            SyncCredentialsResult syncCredentialsResult,
            boolean isCacheHit
    ) {}

}
