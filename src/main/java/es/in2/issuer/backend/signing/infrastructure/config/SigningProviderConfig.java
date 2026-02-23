package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemorySigningProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
@ConditionalOnMissingBean(SigningProvider.class)
@ConditionalOnProperty(prefix = "issuer.signing.runtime", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SigningProviderConfig {

    /**
     * Fallback only for CORE standalone runs.
     * Enterprise should provide its own SigningProvider bean.
     */
    @Bean
    public SigningProvider signingProvider(
            RuntimeSigningConfig runtimeSigningConfig,
            InMemorySigningProvider inMemorySigningProvider
    ) {
        Map<String, SigningProvider> map = new HashMap<>();
        map.put("in-memory", inMemorySigningProvider);

        return new DelegatingSigningProvider(runtimeSigningConfig, map);
    }
}

