package es.in2.issuer.backend.dome.infrastructure.config;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

@Configuration
@EnableConfigurationProperties(KeyMigrationProperties.class)
public class KeyMigrationConfiguration {

    @Bean
    @Lazy
    @Profile("key-migration")
    public KmsAsyncClient kmsAsyncClient() {
        return KmsAsyncClient.create();
    }

    @Bean("vaultWebClient")
    @Lazy
    @Profile("key-migration")
    public WebClient vaultWebClient(WebClient.Builder webClientBuilder,
                                    KeyMigrationProperties properties) {
        return webClientBuilder.baseUrl(properties.vaultEndpoint()).build();
    }
}

