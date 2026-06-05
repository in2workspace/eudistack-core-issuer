package es.in2.issuer.backend.dome.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.DomeSyncFixtureFactory;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.IdempotencyCachePort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsAuditLogger;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsMetrics;
import es.in2.issuer.backend.shared.domain.util.Constants;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ResyncCredentialsWorkflowTest {

    @Mock private TenantConfigPort tenantConfigPort;
    @Mock private IdempotencyCachePort idempotencyCachePort;
    @Mock private CredentialSyncPort credentialSyncPort;
    @Mock private SyncCredentialsMetrics metrics;
    @Mock private SyncCredentialsAuditLogger auditLogger;

    private ResyncCredentialsWorkflow workflow;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private IdempotencyKey idempotencyKey;
    private HolderKeyThumbprint thumbprint;
    private SyncCredentialsResult mockCredentialsResult;
    private List<JsonNode> credentialList;


    @BeforeEach
    void setUp() {
        workflow = new ResyncCredentialsWorkflow(
                tenantConfigPort, idempotencyCachePort, credentialSyncPort, metrics, auditLogger);

        idempotencyKey = new IdempotencyKey(UUID.fromString(DomeSyncFixtureFactory.generateIdempotencyKey()));
        thumbprint = new HolderKeyThumbprint(DomeSyncFixtureFactory.HOLDER_1_THUMBPRINT);
        credentialList = new ArrayList<>();

        try {
            String jsonString = DomeSyncFixtureFactory.getHolder1CredentialsResponse();
            JsonNode rootNode = objectMapper.readTree(jsonString);

            if (rootNode.isArray()) {
                rootNode.forEach(credentialList::add);
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException("Failed to parse fixture JSON in setUp", e);
        }
        mockCredentialsResult = new SyncCredentialsResult(credentialList);
    }

    @Test
    @DisplayName("AC-04: Cache Hit. Must return cached data without querying DB")
    void executeWithCacheHit() {
        when(tenantConfigPort.requireConfig(Constants.TENANT_DOME)).thenReturn(Mono.empty());
        when(idempotencyCachePort.get(any(IdempotencyCacheKey.class)))
                .thenReturn(Mono.just(Optional.of(mockCredentialsResult)));

        StepVerifier.create(workflow.execute(Constants.TENANT_DOME, idempotencyKey, thumbprint))
                .expectNextMatches(result ->
                        result.isCacheHit() &&
                                result.syncCredentialsResult().credentials().size() == credentialList.size())
                .verifyComplete();

        verify(auditLogger).logSyncEvent(Constants.TENANT_DOME, idempotencyKey.value().toString(), "SUCCESS_CACHE_HIT");
        verify(metrics).recordRecoveryAttempt(Constants.TENANT_DOME, "SUCCESS", "CACHE_HIT", true, "RECOVERY");
        verify(credentialSyncPort, never()).findByHolderKey(anyString(), any());
        verify(metrics).recordRecoveryDuration(any());
    }

    @Test
    @DisplayName("ES-02: Happy Path (Cache Miss) - Queries DB, saves to cache and returns data")
    void executeWithCacheMiss() {
        when(tenantConfigPort.requireConfig(Constants.TENANT_DOME))
                .thenReturn(Mono.empty());
        when(idempotencyCachePort.get(any(IdempotencyCacheKey.class)))
                .thenReturn(Mono.just(Optional.empty()));
        when(credentialSyncPort.findByHolderKey(Constants.TENANT_DOME, thumbprint))
                .thenReturn(Flux.fromIterable(credentialList));
        when(idempotencyCachePort.put(any(IdempotencyCacheKey.class), any(SyncCredentialsResult.class)))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute(Constants.TENANT_DOME, idempotencyKey, thumbprint))
                .expectNextMatches(result ->
                        !result.isCacheHit() &&
                                result.syncCredentialsResult().credentials().size() == credentialList.size())
                .verifyComplete();

        verify(auditLogger).logSyncEvent(Constants.TENANT_DOME, idempotencyKey.value().toString(), "SUCCESS_DB_FETCH");
        verify(metrics).recordRecoveryAttempt(Constants.TENANT_DOME, "SUCCESS", "DB_FETCH", false, "RECOVERY");
        verify(idempotencyCachePort).put(any(IdempotencyCacheKey.class), any(SyncCredentialsResult.class));
        verify(metrics).recordRecoveryDuration(any());
    }

    @Test
    @DisplayName("ES-06, ES-07: DB Error or Timeout must propagate exception and log it")
    void executeWithDatabaseError() {
        when(tenantConfigPort.requireConfig(Constants.TENANT_DOME))
                .thenReturn(Mono.empty());

        when(idempotencyCachePort.get(any(IdempotencyCacheKey.class)))
                .thenReturn(Mono.just(Optional.empty()));

        when(credentialSyncPort.findByHolderKey(Constants.TENANT_DOME, thumbprint))
                .thenReturn(Flux.error(new RuntimeException("DB Connection Refused")));

        StepVerifier.create(workflow.execute(Constants.TENANT_DOME, idempotencyKey, thumbprint))
                .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                        throwable.getMessage().equals("DB Connection Refused"))
                .verify();

        verify(auditLogger).logSyncEvent(Constants.TENANT_DOME, idempotencyKey.value().toString(), "ERROR_RuntimeException");
        verify(metrics).recordRecoveryAttempt(Constants.TENANT_DOME, "ERROR", "RuntimeException", false, "RECOVERY");
        verify(idempotencyCachePort, never()).put(any(), any());
        verify(metrics).recordRecoveryDuration(any());
    }

}
