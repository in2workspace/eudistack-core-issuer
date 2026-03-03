package es.in2.issuer.backend.signing.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.service.SigningRecoveryService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignDocSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignHashSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemorySigningProvider;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
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
            SigningRecoveryService signingRecoveryService,

            QtspAuthClient qtspAuthClient,
            QtspIssuerService qtspIssuerService,
            JwsSignHashService jwsSignHashService,
            JadesHeaderBuilderService jadesHeaderBuilder,
            CscSigningProperties cscSigningProperties,
            ObjectMapper objectMapper,

            @Value("${signing.certificate.cert-path:}") String certPath,
            @Value("${signing.certificate.key-path:}") String keyPath
    ) {
        Map<String, SigningProvider> map = new HashMap<>();

        if (certPath.isBlank() || keyPath.isBlank()) {
            throw new IllegalStateException(
                    "Credential signing requires an X.509 certificate. " +
                    "Configure signing.certificate.cert-path and signing.certificate.key-path " +
                    "with paths to the signing certificate and private key PEM files.");
        }

        log.info("Local x509 certificate configured — in-memory provider will use x5c header");
        map.put("in-memory", new InMemorySigningProvider(certPath, keyPath));

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