package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "signing.remote-signature")
public record RemoteSignatureProperties(
        String url,
        String clientId,
        String clientSecret,
        String credentialId,
        String credentialPassword,
        String certificateInfoCacheTtl,
        String signingOperation
) {
    public boolean isConfigured() {
        return url != null && !url.isBlank()
                && clientId != null && !clientId.isBlank()
                && credentialId != null && !credentialId.isBlank();
    }
}
