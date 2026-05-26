package es.in2.issuer.backend.dome.application.workflow;

import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.IdempotencyCachePort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
public class ResyncCredentialsWorkflow {

    private final TenantConfigPort tenantConfigPort;
    private final IdempotencyCachePort idempotencyCachePort;
    private final CredentialSyncPort credentialSyncPort;

    public ResyncCredentialsWorkflow(TenantConfigPort tenantConfigPort,
                                     IdempotencyCachePort idempotencyCachePort,
                                     CredentialSyncPort credentialSyncPort) {
        this.tenantConfigPort = tenantConfigPort;
        this.idempotencyCachePort = idempotencyCachePort;
        this.credentialSyncPort = credentialSyncPort;
    }

    public Mono<ResyncWorkflowResult> execute(String tenant, IdempotencyKey idempotencyKey, HolderKeyThumbprint thumbprint) {
        IdempotencyCacheKey cacheKey = new IdempotencyCacheKey(tenant, idempotencyKey, thumbprint);

        return tenantConfigPort.requireConfig(tenant)
                .then(idempotencyCachePort.get(cacheKey))
                .flatMap(optionalChacheResult -> {
                    if (optionalChacheResult.isPresent()) {
                        return Mono.just(new ResyncWorkflowResult(optionalChacheResult.get(), true));
                    }
                    else {
                        return credentialSyncPort.findByHolderKey(tenant, thumbprint)
                                .collectList()
                                .timeout(Duration.ofSeconds(5))
                                .map(credentialsList -> new SyncCredentialsResult(credentialsList))
                                .flatMap(newResult -> idempotencyCachePort.put(cacheKey, newResult)
                                        .thenReturn(new ResyncWorkflowResult(newResult, false)));

                    }
                });
    }

    public record ResyncWorkflowResult(
            SyncCredentialsResult syncCredentialsResult,
            boolean isCacheHit
    ) {}

}
