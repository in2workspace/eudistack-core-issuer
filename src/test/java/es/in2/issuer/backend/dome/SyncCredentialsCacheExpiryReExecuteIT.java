package es.in2.issuer.backend.dome;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsAuditLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsCacheExpiryReExecuteIT {

    public static class FakeTicker implements Ticker {
        private long nanos = System.nanoTime();
        public void advance(long duration, TimeUnit unit) {
            this.nanos += unit.toNanos(duration);
        }
        @Override
        public long read() {
            return nanos;
        }
    }

    @TestConfiguration
    static class CacheTimeTravelConfig {
        @Bean
        public FakeTicker fakeTicker() {
            return new FakeTicker();
        }

        @Bean
        @Primary
        public Cache<IdempotencyCacheKey, SyncCredentialsResult> timeTravelCache(FakeTicker ticker) {
            return Caffeine.newBuilder()
                    .expireAfterWrite(Duration.ofMinutes(5))
                    .ticker(ticker)
                    .maximumSize(10_000)
                    .build();
        }
    }

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private FakeTicker fakeTicker;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @MockitoBean
    private SyncCredentialsAuditLogger auditLogger;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("EC-05 + NFR-S-144-02: Idempotency cache expires after TTL and re-executes query")
    void syncCredentialsCacheExpiry() {
        String idempotencyKey = "018f2a99-9b80-7fc4-a82f-2c8e3100b468";
        String thumbprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        JsonNode mockCredential = objectMapper.createObjectNode()
                .put("format", "vc+sd-jwt")
                .put("credential", "dummy-jwt");

        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any())).thenReturn(Flux.just(mockCredential));

        String requestBody = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, thumbprint);

        // 1. FIRST REQUEST (Cache Miss -> Hits DB)
        webTestClient.mutateWith(csrf())
                .mutateWith(mockJwt().jwt(b -> b.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post().uri("/internal/dome/sync-credentials")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody)
                .exchange().expectStatus().isOk()
                .expectHeader().doesNotExist("Idempotent-Replay");

        // 2. TIME TRAVEL: Advance the clock by 5 minutes and 1 second (301 seconds)
        fakeTicker.advance(301, TimeUnit.SECONDS);

        // 3. SECOND REQUEST (Cache Expired -> Hits DB Again)
        webTestClient.mutateWith(csrf())
                .mutateWith(mockJwt().jwt(b -> b.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post().uri("/internal/dome/sync-credentials")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody)
                .exchange().expectStatus().isOk()
                .expectHeader().doesNotExist("Idempotent-Replay"); // No header because it's a fresh execution

        // 4. VERIFY: The DB was hit exactly twice because the cache expired
        verify(credentialSyncPort, times(2)).findByHolderKey(anyString(), any());
    }
}
