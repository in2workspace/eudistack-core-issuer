package es.in2.issuer.backend.signing.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignDocSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignHashSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Slf4j
@Configuration
@ConditionalOnProperty(prefix = "issuer.signing.runtime", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SigningProviderConfig {

    @Bean
    @ConditionalOnMissingBean(SigningProvider.class)
    public SigningProvider signingProvider(
            RuntimeSigningConfig runtimeSigningConfig,

            RemoteSignatureService remoteSignatureService,

            QtspAuthClient qtspAuthClient,
            QtspIssuerService qtspIssuerService,
            JwsSignHashService jwsSignHashService,
            JadesHeaderBuilderService jadesHeaderBuilder,
            CscSigningProperties cscSigningProperties,
            ObjectMapper objectMapper
    ) {
        Map<String, SigningProvider> operationMap = Map.of(
                DelegatingSigningProvider.OP_SIGN_DOC, new CscSignDocSigningProvider(remoteSignatureService),
                DelegatingSigningProvider.OP_SIGN_HASH, new CscSignHashSigningProvider(
                        qtspAuthClient,
                        qtspIssuerService,
                        jwsSignHashService,
                        jadesHeaderBuilder,
                        cscSigningProperties,
                        objectMapper
                )
        );

        log.info("Signing operations registered: {}", operationMap.keySet());
        return new DelegatingSigningProvider(runtimeSigningConfig, operationMap);
    }
}
