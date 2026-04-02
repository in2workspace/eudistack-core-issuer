package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.port.SigningRuntimeProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.RemoteSignatureProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.SigningRuntimeConfigProperties;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
public class RuntimeSigningConfig implements SigningRuntimeProperties {

    private final AtomicReference<String> provider;
    @Getter @Setter
    private RemoteSignatureDto remoteSignature;

    public RuntimeSigningConfig(
            SigningRuntimeConfigProperties runtimeProps,
            RemoteSignatureProperties remoteProps
    ) {
        this.provider = new AtomicReference<>(runtimeProps.defaultProvider());

        if (remoteProps.isConfigured()) {
            this.remoteSignature = new RemoteSignatureDto(
                    remoteProps.url(),
                    remoteProps.clientId(),
                    remoteProps.clientSecret(),
                    remoteProps.credentialId(),
                    remoteProps.credentialPassword(),
                    remoteProps.certificateInfoCacheTtl(),
                    remoteProps.signingOperation()
            );
            log.info("Default QTSP provider: '{}' → {} (operation: {})",
                    runtimeProps.defaultProvider(), remoteProps.url(), remoteProps.signingOperation());
        } else {
            log.warn("No default remote signature config — provider '{}' will require runtime push",
                    runtimeProps.defaultProvider());
        }
    }

    public String getProvider() {
        return provider.get();
    }

    public void setProvider(String provider) {
        this.provider.set(provider);
    }
}
