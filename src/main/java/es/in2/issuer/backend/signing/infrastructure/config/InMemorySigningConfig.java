package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemoryKeyMaterialLoader;
import es.in2.issuer.backend.signing.infrastructure.properties.DefaultSignerProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.InMemorySigningProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class InMemorySigningConfig {

    private final ConfigAdapter configAdapter;
    private final InMemorySigningProperties props;

    public InMemorySigningConfig(ConfigAdapterFactory factory, InMemorySigningProperties props) {
        this.configAdapter = factory.getAdapter();
        this.props = props;
    }

    @Bean
    public InMemoryKeyMaterialLoader.KeyMaterial inMemoryKeyMaterialOrNull() {

        if (props.hasPaths()) {
            String keyPath = configAdapter.getConfiguration(props.keyPath());
            String certPath = configAdapter.getConfiguration(props.certChainPath());
            return InMemoryKeyMaterialLoader.loadFromPaths(keyPath, certPath);
        }

        if (props.hasInlinePemKeys()) {
            String keyPem = normalizePem(configAdapter.getConfiguration(props.privateKeyPem()));
            String chainPem = normalizePem(configAdapter.getConfiguration(props.certChainPem()));
            return InMemoryKeyMaterialLoader.loadFromPemStrings(keyPem, chainPem);
        }

        return null;
    }

    private static String normalizePem(String pem) {
        if (pem == null) return null;
        return pem.replace("\\n", "\n").replace("\r", "").trim();
    }
}
