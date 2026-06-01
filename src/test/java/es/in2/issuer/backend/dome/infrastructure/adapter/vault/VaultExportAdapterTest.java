package es.in2.issuer.backend.dome.infrastructure.adapter.vault;

import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("VaultExportAdapter — Vault transit export")
class VaultExportAdapterTest {

    private static final LegacyKeyId KEY_ID = new LegacyKeyId("test-key-id");

    private VaultExportAdapter adapterWith(String jsonBody) {
        ExchangeFunction exchangeFunction = request -> Mono.just(
                ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .body(jsonBody)
                        .build());
        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        return new VaultExportAdapter(webClient);
    }

    private VaultExportAdapter adapterWithError(Throwable error) {
        ExchangeFunction exchangeFunction = request -> Mono.error(error);
        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        return new VaultExportAdapter(webClient);
    }

    @Nested
    @DisplayName("success paths")
    class SuccessPaths {

        @Test
        @DisplayName("single key version — returns decoded bytes")
        void exportPrivateKey_singleVersion_returnsDecodedBytes() {
            // Arrange
            byte[] rawKey = {0x01, 0x02, 0x03, 0x04};
            String b64 = Base64.getEncoder().encodeToString(rawKey);
            String json = "{\"data\":{\"keys\":{\"1\":\"" + b64 + "\"}}}";

            // Act & Assert
            StepVerifier.create(adapterWith(json).exportPrivateKey(KEY_ID))
                    .assertNext(bytes -> assertThat(bytes).containsExactly(rawKey))
                    .verifyComplete();
        }

        @Test
        @DisplayName("multiple key versions — returns bytes of the highest numeric version")
        void exportPrivateKey_multipleVersions_returnsHighestVersion() {
            // Arrange
            byte[] oldKey = {0x01};
            byte[] newKey = {0x02, 0x03};
            String b64Old = Base64.getEncoder().encodeToString(oldKey);
            String b64New = Base64.getEncoder().encodeToString(newKey);
            String json = "{\"data\":{\"keys\":{\"1\":\"" + b64Old + "\","
                    + "\"3\":\"" + b64New + "\","
                    + "\"2\":\"" + b64Old + "\"}}}";

            // Act & Assert
            StepVerifier.create(adapterWith(json).exportPrivateKey(KEY_ID))
                    .assertNext(bytes -> assertThat(bytes).containsExactly(newKey))
                    .verifyComplete();
        }
    }

    @Nested
    @DisplayName("domain error paths — errors NOT re-wrapped")
    class DomainErrorPaths {

        @Test
        @DisplayName("null keys map — errors with vault_export_empty_keys (not double-wrapped)")
        void exportPrivateKey_nullKeys_errorsWithVaultExportEmptyKeys() {
            // Arrange
            String json = "{\"data\":{\"keys\":null}}";

            // Act & Assert
            StepVerifier.create(adapterWith(json).exportPrivateKey(KEY_ID))
                    .expectErrorMatches(ex ->
                            ex instanceof RuntimeException
                            && ex.getMessage().startsWith("vault_export_empty_keys")
                            && ex.getCause() == null)
                    .verify();
        }

        @Test
        @DisplayName("empty keys map — errors with vault_export_empty_keys (not double-wrapped)")
        void exportPrivateKey_emptyKeys_errorsWithVaultExportEmptyKeys() {
            // Arrange
            String json = "{\"data\":{\"keys\":{}}}";

            // Act & Assert
            StepVerifier.create(adapterWith(json).exportPrivateKey(KEY_ID))
                    .expectErrorMatches(ex ->
                            ex instanceof RuntimeException
                            && ex.getMessage().startsWith("vault_export_empty_keys")
                            && ex.getCause() == null)
                    .verify();
        }

        @Test
        @DisplayName("blank key material for highest version — errors with vault_export_null_key_material")
        void exportPrivateKey_blankKeyMaterial_errorsWithNullKeyMaterial() {
            // Arrange
            String json = "{\"data\":{\"keys\":{\"1\":\"\"}}}";

            // Act & Assert
            StepVerifier.create(adapterWith(json).exportPrivateKey(KEY_ID))
                    .expectErrorMatches(ex ->
                            ex instanceof RuntimeException
                            && ex.getMessage().startsWith("vault_export_null_key_material")
                            && ex.getCause() == null)
                    .verify();
        }
    }

    @Nested
    @DisplayName("infrastructure error paths — errors wrapped as vault_export_failed")
    class InfrastructureErrorPaths {

        @Test
        @DisplayName("WebClient connection failure — wraps as vault_export_failed")
        void exportPrivateKey_webClientConnectionFailure_wrapsAsVaultExportFailed() {
            // Arrange
            VaultExportAdapter adapter =
                    adapterWithError(new IllegalStateException("connection refused"));

            // Act & Assert
            StepVerifier.withVirtualTime(() -> adapter.exportPrivateKey(KEY_ID))
                    .thenAwait(Duration.ofMinutes(1))
                    .expectErrorMatches(ex ->
                            ex instanceof RuntimeException
                            && ex.getMessage().startsWith("vault_export_failed:")
                            && ex.getMessage().contains(KEY_ID.value()))
                    .verify();
        }

        @Test
        @DisplayName("checked exception from infrastructure — wraps as vault_export_failed")
        void exportPrivateKey_checkedInfraException_wrapsAsVaultExportFailed() {
            // Arrange
            VaultExportAdapter adapter =
                    adapterWithError(new java.io.IOException("socket timeout"));

            // Act & Assert
            StepVerifier.withVirtualTime(() -> adapter.exportPrivateKey(KEY_ID))
                    .thenAwait(Duration.ofMinutes(1))
                    .expectErrorMatches(ex ->
                            ex instanceof RuntimeException
                            && ex.getMessage().startsWith("vault_export_failed:")
                            && ex.getMessage().contains(KEY_ID.value()))
                    .verify();
        }
    }
}



