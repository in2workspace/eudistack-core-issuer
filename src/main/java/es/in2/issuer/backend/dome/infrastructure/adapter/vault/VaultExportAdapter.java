package es.in2.issuer.backend.dome.infrastructure.adapter.vault;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Base64;
import java.util.Comparator;
import java.util.Map;

@Component
@Profile("key-migration")
@Slf4j
public class VaultExportAdapter implements VaultExportPort {

    private final WebClient vaultWebClient;

    public VaultExportAdapter(@Qualifier("vaultWebClient") WebClient vaultWebClient) {
        this.vaultWebClient = vaultWebClient;
    }

    @Override
    public Mono<byte[]> exportPrivateKey(LegacyKeyId keyId) {
        return vaultWebClient.get()
                .uri("/v1/transit/export/signing-key/{keyId}", keyId.value())
                .retrieve()
                .bodyToMono(VaultExportResponse.class)
                .timeout(Duration.ofSeconds(30))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)).maxBackoff(Duration.ofSeconds(4)))
                .map(response -> {
                    Map<String, String> keys = response.data().keys();
                    if (keys == null || keys.isEmpty()) {
                        throw new RuntimeException(
                                "vault_export_empty_keys: no key versions returned for keyId=" + keyId.value());
                    }
                    // Select the highest available version (Vault versions are numeric strings)
                    String highestVersion = keys.keySet().stream()
                            .max(Comparator.comparingInt(Integer::parseInt))
                            .orElseThrow(() -> new RuntimeException(
                                    "vault_export_empty_keys: no key versions returned for keyId=" + keyId.value()));
                    String base64Key = keys.get(highestVersion);
                    if (base64Key == null || base64Key.isBlank()) {
                        throw new RuntimeException(
                                "vault_export_null_key_material: version=" + highestVersion
                                + " keyId=" + keyId.value());
                    }
                    return Base64.getDecoder().decode(base64Key);
                })
                .onErrorMap(ex -> {
                    log.warn("Vault export failed for keyId={} error={}", keyId.value(), ex.getMessage(), ex);
                    return new RuntimeException("vault_export_failed: " + keyId.value(), ex);
                });
    }

    private record VaultExportResponse(@JsonProperty("data") VaultExportData data) {}

    private record VaultExportData(@JsonProperty("keys") Map<String, String> keys) {}
}
