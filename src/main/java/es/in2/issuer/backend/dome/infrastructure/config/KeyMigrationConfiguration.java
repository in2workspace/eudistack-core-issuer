package es.in2.issuer.backend.dome.infrastructure.config;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.web.reactive.function.client.WebClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

/**
 * C7 — Beans de infraestructura para key migration: KMS async client (lazy) y
 * Vault WebClient, gated by profile {@code key-migration}.
 */
@Configuration
@EnableConfigurationProperties(KeyMigrationProperties.class)
public class KeyMigrationConfiguration {

    /**
     * Lazily-initialized KMS async client.
     * Not created until first use, allowing the application context to start
     * in environments without AWS credentials configured (e.g., local / test).
     */
    @Bean
    @Lazy
    public KmsAsyncClient kmsAsyncClient() {
        return KmsAsyncClient.create();
    }

    @Bean("vaultWebClient")
    @Lazy
    public WebClient vaultWebClient(WebClient.Builder webClientBuilder,
                                    KeyMigrationProperties properties) {
        return webClientBuilder.baseUrl(properties.vaultEndpoint()).build();
    }
}

