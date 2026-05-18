package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import reactor.core.publisher.Mono;

import java.util.List;

public interface CscPort {

    Mono<String> requestAccessToken(RemoteSignatureDto cfg, String scope, boolean includeAuthDetails, String credentialData);

    default Mono<String> requestAccessToken(RemoteSignatureDto cfg, String scope, boolean includeAuthDetails) {
        return requestAccessToken(cfg, scope, includeAuthDetails, null);
    }

    Mono<CertificateInfo> getCredentialInfo(RemoteSignatureDto cfg, String accessToken, String credentialId);

    Mono<Boolean> validateCredentialId(RemoteSignatureDto cfg, String accessToken, String credentialId);

    Mono<String> authorizeForHash(RemoteSignatureDto cfg, String accessToken, String hashB64Url, String hashAlgoOid);

    Mono<String> signHash(RemoteSignatureDto cfg, String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid);

    Mono<String> authorizeForDoc(RemoteSignatureDto cfg, String accessToken);

    Mono<String> signDoc(RemoteSignatureDto cfg, String accessToken, String sad, String docB64, String signAlgoOid);

    Mono<List<String>> listCredentialIds(RemoteSignatureDto cfg, String accessToken);

}
