package es.in2.issuer.backend.dome.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.IdempotencyCachePort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsAuditLogger;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ResyncCredentialsWorkflowTest {

    @Mock
    private TenantConfigPort tenantConfigPort;

    @Mock
    private IdempotencyCachePort idempotencyCachePort;

    @Mock
    private CredentialSyncPort credentialSyncPort;

    @Mock
    private SyncCredentialsMetrics metrics;

    @Mock
    private SyncCredentialsAuditLogger auditLogger;

    @InjectMocks
    private ResyncCredentialsWorkflow workflow;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String tenant = "default-tenant";
    private IdempotencyKey idempotencyKey;
    private HolderKeyThumbprint thumbprint;
    private SyncCredentialsResult mockCredentialsResult;
    private JsonNode credential1;
    private JsonNode credential2;

    @BeforeEach
    void setUp() {
        idempotencyKey = new IdempotencyKey(UUID.randomUUID());
        thumbprint = new HolderKeyThumbprint("dummy-thumbprint-123");

        credential1 = objectMapper.createObjectNode().put("key", "dummyValue1");
        credential2 = objectMapper.createObjectNode().put("key", "dummyValue2");

        mockCredentialsResult = new SyncCredentialsResult(List.of(credential1, credential2));
    }

    @Test
    @DisplayName("AC-04: Cache Hit. Must return cached data without querying DB")
    void executeWithCacheHit() {
        when(tenantConfigPort.requireConfig(tenant)).thenReturn(Mono.empty());
        when(idempotencyCachePort.get(any(IdempotencyCacheKey.class)))
                .thenReturn(Mono.just(Optional.of(mockCredentialsResult)));

        StepVerifier.create(workflow.execute(tenant, idempotencyKey, thumbprint))
                .expectNextMatches(result ->
                        result.isCacheHit() &&
                                result.syncCredentialsResult().credentials().size() == 2)
                .verifyComplete();

        verify(auditLogger).logSyncEvent(tenant, idempotencyKey.value().toString(), "SUCCESS_CACHE_HIT");
        verify(metrics).recordRecoveryAttempt(tenant, "SUCCESS", "CACHE_HIT", true, "RECOVERY");
        verify(credentialSyncPort, never()).findByHolderKey(anyString(), any());
        verify(metrics).recordRecoveryDuration(any());
    }

    @Test
    @DisplayName("ES-02: Happy Path (Cache Miss) - Queries DB, saves to cache and returns data")
    void executeWithCacheMiss() {
        when(tenantConfigPort.requireConfig(tenant))
                .thenReturn(Mono.empty());

        when(idempotencyCachePort.get(any(IdempotencyCacheKey.class)))
                .thenReturn(Mono.just(Optional.empty())); // Not in cache

        when(credentialSyncPort.findByHolderKey(tenant, thumbprint))
                .thenReturn(Flux.just(credential1, credential2));

        when(idempotencyCachePort.put(any(IdempotencyCacheKey.class), any(SyncCredentialsResult.class)))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute(tenant, idempotencyKey, thumbprint))
                .expectNextMatches(result ->
                        !result.isCacheHit() &&
                                result.syncCredentialsResult().credentials().size() == 2)
                .verifyComplete();

        verify(auditLogger).logSyncEvent(tenant, idempotencyKey.value().toString(), "SUCCESS_DB_FETCH");
        verify(metrics).recordRecoveryAttempt(tenant, "SUCCESS", "DB_FETCH", false, "RECOVERY");
        verify(idempotencyCachePort).put(any(IdempotencyCacheKey.class), any(SyncCredentialsResult.class));
        verify(metrics).recordRecoveryDuration(any());
    }

    @Test
    @DisplayName("ES-06, ES-07: DB Error or Timeout must propagate exception and log it")
    void executeWithDatabaseError() {
        when(tenantConfigPort.requireConfig(tenant))
                .thenReturn(Mono.empty());

        when(idempotencyCachePort.get(any(IdempotencyCacheKey.class)))
                .thenReturn(Mono.just(Optional.empty()));

        when(credentialSyncPort.findByHolderKey(tenant, thumbprint))
                .thenReturn(Flux.error(new RuntimeException("DB Connection Refused")));

        StepVerifier.create(workflow.execute(tenant, idempotencyKey, thumbprint))
                .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                        throwable.getMessage().equals("DB Connection Refused"))
                .verify();

        verify(auditLogger).logSyncEvent(tenant, idempotencyKey.value().toString(), "ERROR_RuntimeException");
        verify(metrics).recordRecoveryAttempt(tenant, "ERROR", "RuntimeException", false, "RECOVERY");
        verify(idempotencyCachePort, never()).put(any(), any());
        verify(metrics).recordRecoveryDuration(any());
    }

}
