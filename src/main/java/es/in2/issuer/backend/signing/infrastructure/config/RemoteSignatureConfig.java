package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.signing.infrastructure.properties.RemoteSignatureProperties;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RemoteSignatureConfig {

    private final ConfigAdapter configAdapter;
    private final RemoteSignatureProperties remoteSignatureProperties;

    public RemoteSignatureConfig(ConfigAdapterFactory configAdapterFactory, RemoteSignatureProperties remoteSignatureProperties) {
        this.configAdapter = configAdapterFactory.getAdapter();
        this.remoteSignatureProperties = remoteSignatureProperties;
    }

    public String getRemoteSignatureDomain() {
        return configAdapter.getConfiguration(remoteSignatureProperties.url());
    }

    public String getRemoteSignatureSignPath() {
        return configAdapter.getConfiguration(remoteSignatureProperties.paths().signPath());
    }

    public String getRemoteSignatureClientId() {
        return configAdapter.getConfiguration(remoteSignatureProperties.clientId());
    }

    public String getRemoteSignatureClientSecret() {
        return configAdapter.getConfiguration(remoteSignatureProperties.clientSecret());
    }

    public String getRemoteSignatureCredentialId() {
        return configAdapter.getConfiguration(remoteSignatureProperties.credentialId());
    }

    public String getRemoteSignatureCredentialPassword() {
        return configAdapter.getConfiguration(remoteSignatureProperties.credentialPassword());
    }

    public String getRemoteSignatureType() {
        return configAdapter.getConfiguration(remoteSignatureProperties.type());
    }

    public Duration getCertificateInfoCacheTtl() {
        String raw = configAdapter.getConfiguration(remoteSignatureProperties.certificateInfoCacheTtl());
        return DurationStyle.detectAndParse(raw);
    }

    
}
