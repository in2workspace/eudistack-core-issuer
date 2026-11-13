package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import es.in2.issuer.backend.shared.infrastructure.adapter.LocalTenantSecretKeyAdapter;
import es.in2.issuer.backend.shared.infrastructure.adapter.SsmTenantSecretKeyAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.properties.SearchIdentifierProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.SsmAsyncClientBuilder;

import java.time.Duration;

/**
 * The secret key of each tenant (EUD-267). Outside the {@code local} profile it is read from Parameter Store, and a
 * local seed is refused at startup: a key derived from a seed in the configuration must never protect real data
 * (SEC-17). With the {@code local} profile it is derived from that seed.
 *
 * <p>Without {@code issuer.search-identifiers.key-parameter} the issuer still starts: only an issuance of a type with
 * search identifiers fails, and the background calculation waits for the key.
 */
@Slf4j
@Configuration
public class TenantSecretKeyConfig {

    /** SDK backstop, a bit above the Reactor timeout of the adapter, which is the one that governs. */
    private static final Duration API_CALL_TIMEOUT = Duration.ofSeconds(6);

    @Bean
    @Profile("local")
    TenantSecretKeyPort localTenantSecretKeyPort(SearchIdentifierProperties properties) {
        log.warn("Local profile: the tenant secret keys are derived from issuer.search-identifiers.local-key-seed");
        return new LocalTenantSecretKeyAdapter(properties.localKeySeed());
    }

    @Bean
    @Profile("!local")
    TenantSecretKeyPort ssmTenantSecretKeyPort(SearchIdentifierProperties properties,
                                               ObjectProvider<SsmAsyncClient> ssmAsyncClient) {
        if (properties.localKeySeed() != null && !properties.localKeySeed().isBlank()) {
            throw new IllegalStateException("issuer.search-identifiers.local-key-seed is only allowed with the local "
                    + "profile: the tenant secret keys come from Parameter Store");
        }
        String keyParameter = properties.keyParameter();
        if (keyParameter == null || keyParameter.isBlank()) {
            log.warn("No issuer.search-identifiers.key-parameter: issuances of types with search identifiers will fail");
        } else if (!keyParameter.contains(SearchIdentifierProperties.TENANT_PLACEHOLDER)) {
            throw new IllegalStateException("issuer.search-identifiers.key-parameter must contain "
                    + SearchIdentifierProperties.TENANT_PLACEHOLDER + ": every tenant has its own key");
        }
        return new SsmTenantSecretKeyAdapter(ssmAsyncClient::getObject, keyParameter);
    }

    /** Built by the first read of a key, not at startup: building it needs a region. */
    @Lazy
    @Bean(destroyMethod = "close")
    SsmAsyncClient ssmAsyncClient(SearchIdentifierProperties properties) {
        SsmAsyncClientBuilder builder = SsmAsyncClient.builder()
                .overrideConfiguration(c -> c.apiCallTimeout(API_CALL_TIMEOUT));
        if (properties.endpoint() != null) {
            builder.endpointOverride(properties.endpoint());
        }
        return builder.build();
    }
}
