package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "issuer-identity")
@Validated
public record IssuerIdentityProperties(
        Crypto crypto
) {
    @ConstructorBinding
    public IssuerIdentityProperties(Crypto crypto) {
        this.crypto = crypto != null ? crypto : new Crypto("");
    }

    @Validated
    public record Crypto(String privateKey) {
        public Crypto {
            if (privateKey == null) {
                privateKey = "";
            }
        }
    }
}
