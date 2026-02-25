package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;


@ConfigurationProperties(prefix = "signing.in-memory")
@Validated
public record InMemorySigningProperties (
        String keyPath,
        String certChainPath,
        String privateKeyPem,
        String certChainPem
)
{
    public boolean hasPaths() {
        return keyPath != null && !keyPath.isBlank()
                && certChainPath != null && !certChainPath.isBlank();
    }

    public boolean hasInlinePemKeys() {
        return privateKeyPem != null && !privateKeyPem.isBlank()
                && certChainPem != null && !certChainPem.isBlank();
    }
}