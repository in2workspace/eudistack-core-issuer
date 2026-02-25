package es.in2.issuer.backend.signing.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.service.SigningRecoveryService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.*;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.InMemorySigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Configuration
@EnableConfigurationProperties(InMemorySigningProperties.class)
@ConditionalOnProperty(prefix = "issuer.signing.runtime", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SigningProviderConfig {

    @Bean
    @ConditionalOnMissingBean(SigningProvider.class)
    public SigningProvider signingProvider(
            RuntimeSigningConfig runtimeSigningConfig,

            RemoteSignatureService remoteSignatureService,
            SigningRecoveryService signingRecoveryService,

            QtspAuthClient qtspAuthClient,
            QtspIssuerService qtspIssuerService,
            JwsSignHashService jwsSignHashService,
            JadesHeaderBuilderService jadesHeaderBuilder,
            CscSigningProperties cscSigningProperties,
            ObjectMapper objectMapper,
            InMemoryKeyMaterialLoader.KeyMaterial inMemoryKeyMaterialOrNull
    ) {
        Map<String, SigningProvider> map = new HashMap<>();

        map.put("in-memory",
                inMemoryKeyMaterialOrNull != null
                        ? new InMemorySigningProvider(inMemoryKeyMaterialOrNull)
                        : new InMemorySigningProvider()
        );

        map.put("csc-sign-doc", new CscSignDocSigningProvider(
                remoteSignatureService,
                signingRecoveryService
        ));

        map.put("csc-sign-hash", new CscSignHashSigningProvider(
                qtspAuthClient,
                qtspIssuerService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties,
                objectMapper
        ));

        return new DelegatingSigningProvider(runtimeSigningConfig, map);
    }


}