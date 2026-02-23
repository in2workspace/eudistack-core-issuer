package es.in2.issuer.backend.signing.infrastructure.config;

import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

@Component
public class RuntimeSigningConfig {

    private final AtomicReference<String> provider = new AtomicReference<>("in-memory");

    public String getProvider() {
        return provider.get();
    }

    public void setProvider(String provider) {
        this.provider.set(provider);
    }
}
