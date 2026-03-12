package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.port.SigningRuntimeProperties;
import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

@Component
public class RuntimeSigningConfig implements SigningRuntimeProperties {

    private final AtomicReference<String> provider = new AtomicReference<>("in-memory");
    @Getter @Setter
    private RemoteSignatureDto remoteSignature;

    public String getProvider() {
        return provider.get();
    }

    public void setProvider(String provider) {
        this.provider.set(provider);
    }

}
