package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import reactor.core.publisher.Mono;

public interface IssuerCertificateService {
    Mono<Boolean> validateCredentials(RemoteSignatureDto cfg);
    Mono<CertificateInfo> requestCertificateInfo(RemoteSignatureDto cfg, String accessToken, String credentialId);
    Mono<DetailedIssuer> resolveRemoteDetailedIssuer(RemoteSignatureDto cfg);
}
