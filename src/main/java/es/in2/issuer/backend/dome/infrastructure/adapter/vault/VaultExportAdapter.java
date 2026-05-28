package es.in2.issuer.backend.dome.infrastructure.adapter.vault;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;

@Component
@Profile("key-migration")
@RequiredArgsConstructor
@Slf4j
public class VaultExportAdapter implements VaultExportPort {

    @Qualifier("vaultWebClient")
    private final WebClient vaultWebClient;

    @Override
    public Mono<byte[]> exportPrivateKey(LegacyKeyId keyId) {
        return vaultWebClient.get()
                .uri("/v1/transit/export/signing-key/{keyId}", keyId.value())
                .retrieve()
                .bodyToMono(VaultExportResponse.class)
                .timeout(Duration.ofSeconds(30))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)).maxBackoff(Duration.ofSeconds(4)))
                .map(response -> {
                    String base64Key = response.data().keys().get("1");
                    return Base64.getDecoder().decode(base64Key);
                })
                .onErrorMap(ex -> {
                    log.warn("Vault export failed for keyId={} exception={}", keyId.value(),
                            ex.getClass().getName());
                    return new RuntimeException("vault_export_failed: " + keyId.value(), ex);
                });
    }

    private record VaultExportResponse(@JsonProperty("data") VaultExportData data) {}

    private record VaultExportData(@JsonProperty("keys") Map<String, String> keys) {}
}

