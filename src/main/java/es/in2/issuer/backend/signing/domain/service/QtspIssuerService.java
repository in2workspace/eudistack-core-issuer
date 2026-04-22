package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import reactor.core.publisher.Mono;

/**
 * Resolves QTSP-backed issuer identity (certificate info, organizationIdentifier).
 * All methods receive the tenant-resolved {@link RemoteSignatureDto} explicitly.
 */
public interface QtspIssuerService {
    Mono<Boolean> validateCredentials(RemoteSignatureDto cfg);
    Mono<String> requestCertificateInfo(RemoteSignatureDto cfg, String accessToken, String credentialID);
    Mono<DetailedIssuer> extractIssuerFromCertificateInfo(String certificateInfo);
    Mono<DetailedIssuer> resolveRemoteDetailedIssuer(RemoteSignatureDto cfg);
}
