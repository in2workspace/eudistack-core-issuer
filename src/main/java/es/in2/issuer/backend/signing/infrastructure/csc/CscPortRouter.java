package es.in2.issuer.backend.signing.infrastructure.csc;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Primary
@Component
public class CscPortRouter implements CscPort {

    private final Map<CscApiVersion, CscPort> adaptersByVersion;

    public CscPortRouter(List<CscPort> adapters) {
        Map<CscApiVersion, CscPort> map = new EnumMap<>(CscApiVersion.class);
        for (CscPort adapter : adapters) {
            CscApiVersion version = CscApiVersion.fromValue(adapter.supportedVersion());
            CscPort previous = map.putIfAbsent(version, adapter);
            if (previous != null) {
                throw new IllegalStateException(
                        "Duplicate CscPort registration for version " + adapter.supportedVersion());
            }
        }
        this.adaptersByVersion = Map.copyOf(map);
        log.info("CSC adapters registered for versions: {}", adaptersByVersion.keySet());
    }

    @Override
    public String supportedVersion() {
        throw new UnsupportedOperationException("CscPortRouter is a router, not a versioned adapter");
    }

    @Override
    public Mono<String> requestAccessToken(RemoteSignatureDto cfg, String scope, boolean includeAuthDetails, String credentialData) {
        return resolve(cfg).requestAccessToken(cfg, scope, includeAuthDetails, credentialData);
    }

    @Override
    public Mono<CertificateInfo> getCredentialInfo(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        return resolve(cfg).getCredentialInfo(cfg, accessToken, credentialId);
    }

    @Override
    public Mono<Boolean> validateCredentialId(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        return resolve(cfg).validateCredentialId(cfg, accessToken, credentialId);
    }

    @Override
    public Mono<List<String>> listCredentialIds(RemoteSignatureDto cfg, String accessToken) {
        return resolve(cfg).listCredentialIds(cfg, accessToken);
    }

    @Override
    public Mono<String> authorizeForHash(RemoteSignatureDto cfg, String accessToken, String hashB64Url, String hashAlgoOid) {
        return resolve(cfg).authorizeForHash(cfg, accessToken, hashB64Url, hashAlgoOid);
    }

    @Override
    public Mono<String> signHash(RemoteSignatureDto cfg, String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid) {
        return resolve(cfg).signHash(cfg, accessToken, sad, hashB64Url, hashAlgoOid, signAlgoOid);
    }

    @Override
    public Mono<String> authorizeForDoc(RemoteSignatureDto cfg, String accessToken) {
        return resolve(cfg).authorizeForDoc(cfg, accessToken);
    }

    @Override
    public Mono<String> signDoc(RemoteSignatureDto cfg, String accessToken, String sad, String docB64, String signAlgoOid) {
        return resolve(cfg).signDoc(cfg, accessToken, sad, docB64, signAlgoOid);
    }

    private CscPort resolve(RemoteSignatureDto cfg) {
        CscApiVersion version = CscApiVersion.fromValue(cfg.cscApiVersion());
        CscPort adapter = adaptersByVersion.get(version);
        if (adapter == null) {
            throw new IllegalArgumentException("No CscPort adapter registered for version: " + version);
        }
        return adapter;
    }
}
