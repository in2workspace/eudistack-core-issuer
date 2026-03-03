package es.in2.issuer.backend.shared.infrastructure.crypto;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class CryptoConfig {

    private final AppConfig appConfig;

    /**
     * Returns the AS private key hex string, or null/blank if not configured
     * (in which case CryptoComponent will auto-generate an ephemeral key).
     */
    public String getPrivateKey() {
        String privateKey = appConfig.getCryptoPrivateKey();
        if (privateKey == null || privateKey.isBlank()) {
            return null;
        }
        if (privateKey.startsWith("0x")) {
            privateKey = privateKey.substring(2);
        }
        return privateKey;
    }
}
