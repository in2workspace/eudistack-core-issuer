package es.in2.issuer.backend.dome.infrastructure.adapter.vault;

import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class VaultBYOKExportAdapter implements VaultExportPort {

    /** Field name matches bean name "vaultWebClient" — Spring resolves by name among multiple WebClient beans. */
    private final WebClient vaultWebClient;

    @Override
    public Mono<EncryptedKeyEnvelope> exportWrapped(LegacyKeyId keyId,
                                                    String kmsWrappingKeyPublicKey) {
        log.debug("Requesting BYOK transit export from Vault for key");
        return vaultWebClient.post()
                .uri("/v1/transit/export/signing-key/{keyName}", keyId.value())
                .bodyValue(Map.of("wrapping_key", kmsWrappingKeyPublicKey))
                .retrieve()
                .bodyToMono(VaultExportResponse.class)
                .map(response -> {
                    byte[] ciphertext = Base64.getDecoder().decode(response.data().ciphertext());
                    log.debug("Vault BYOK export completed successfully");
                    return new EncryptedKeyEnvelope(ciphertext, "RSAES_OAEP_SHA_256", "");
                })
                .timeout(Duration.ofSeconds(30))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
                        .maxBackoff(Duration.ofSeconds(4)))
                .onErrorMap(WebClientException.class, e -> {
                    log.warn("Vault unavailable during BYOK export: {}", e.getMessage());
                    return new RuntimeException("vault_unavailable: " + e.getMessage(), e);
                });
    }

    private record VaultExportResponse(VaultData data) {}

    private record VaultData(String ciphertext) {}
}


