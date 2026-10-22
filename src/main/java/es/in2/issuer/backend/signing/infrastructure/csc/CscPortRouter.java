package es.in2.issuer.backend.signing.infrastructure.csc;

import es.in2.issuer.backend.shared.domain.model.audit.ExternalSystemTarget;
import es.in2.issuer.backend.shared.infrastructure.audit.ExternalSystemAccessRecorder;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthProvider;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Primary
@Component
public class CscPortRouter implements CscPort {

    private static final String UNKNOWN_QTSP = "unknown";
    private static final String OPERATION_ACCESS_TOKEN = "oauth2/token";
    private static final String OPERATION_CREDENTIALS_INFO = "credentials/info";
    private static final String OPERATION_CREDENTIALS_LIST = "credentials/list";
    private static final String OPERATION_CREDENTIALS_AUTHORIZE = "credentials/authorize";
    private static final String OPERATION_SIGN_HASH = "signatures/signHash";
    private static final String OPERATION_SIGN_DOC = "signatures/signDoc";

    private final Map<CscApiVersion, CscPort> adaptersByVersion;
    private final ExternalSystemAccessRecorder accessRecorder;

    public CscPortRouter(List<CscPort> adapters, ExternalSystemAccessRecorder accessRecorder) {
        this.accessRecorder = accessRecorder;
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
        return audited(cfg, OPERATION_ACCESS_TOKEN,
                resolve(cfg).requestAccessToken(cfg, scope, includeAuthDetails, credentialData));
    }

    @Override
    public Mono<CertificateInfo> getCredentialInfo(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        return audited(cfg, OPERATION_CREDENTIALS_INFO, resolve(cfg).getCredentialInfo(cfg, accessToken, credentialId));
    }

    @Override
    public Mono<Boolean> validateCredentialId(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        return audited(cfg, OPERATION_CREDENTIALS_LIST, resolve(cfg).validateCredentialId(cfg, accessToken, credentialId));
    }

    @Override
    public Mono<List<String>> listCredentialIds(RemoteSignatureDto cfg, String accessToken) {
        return audited(cfg, OPERATION_CREDENTIALS_LIST, resolve(cfg).listCredentialIds(cfg, accessToken));
    }

    @Override
    public Mono<String> authorizeForHash(RemoteSignatureDto cfg, String accessToken, String hashB64Url, String hashAlgoOid) {
        return audited(cfg, OPERATION_CREDENTIALS_AUTHORIZE,
                resolve(cfg).authorizeForHash(cfg, accessToken, hashB64Url, hashAlgoOid));
    }

    @Override
    public Mono<String> signHash(RemoteSignatureDto cfg, String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid) {
        return audited(cfg, OPERATION_SIGN_HASH,
                resolve(cfg).signHash(cfg, accessToken, sad, hashB64Url, hashAlgoOid, signAlgoOid));
    }

    @Override
    public Mono<String> authorizeForDoc(RemoteSignatureDto cfg, String accessToken) {
        return audited(cfg, OPERATION_CREDENTIALS_AUTHORIZE, resolve(cfg).authorizeForDoc(cfg, accessToken));
    }

    @Override
    public Mono<String> signDoc(RemoteSignatureDto cfg, String accessToken, String sad, String docB64, String signAlgoOid) {
        return audited(cfg, OPERATION_SIGN_DOC, resolve(cfg).signDoc(cfg, accessToken, sad, docB64, signAlgoOid));
    }

    /** Every call to the QTSP is an access to a third party, whichever protocol version makes it. */
    private <T> Mono<T> audited(RemoteSignatureDto cfg, String operation, Mono<T> call) {
        return accessRecorder.recordAccess(qtspOf(cfg), operation, call);
    }

    private static ExternalSystemTarget qtspOf(RemoteSignatureDto cfg) {
        return ExternalSystemTarget.qtsp(hostOf(cfg.url()), authenticationMethodOf(cfg.provider()));
    }

    /** The audit must never be what fails a call: an unusable url is named {@code unknown}, and the call reports its own error. */
    private static String hostOf(String url) {
        if (url == null || url.isBlank()) {
            return UNKNOWN_QTSP;
        }
        try {
            String host = URI.create(url).getHost();
            return host != null ? host : UNKNOWN_QTSP;
        } catch (IllegalArgumentException e) {
            return UNKNOWN_QTSP;
        }
    }

    private static String authenticationMethodOf(String provider) {
        return CscAuthProvider.fromValue(provider)
                .map(known -> known == CscAuthProvider.VINTEGRIS
                        ? ExternalSystemTarget.AUTHENTICATION_API_KEY
                        : ExternalSystemTarget.AUTHENTICATION_OAUTH_CLIENT_CREDENTIALS)
                .orElse(ExternalSystemTarget.AUTHENTICATION_NONE);
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
