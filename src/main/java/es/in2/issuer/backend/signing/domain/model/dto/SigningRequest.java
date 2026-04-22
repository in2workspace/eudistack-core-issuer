package es.in2.issuer.backend.signing.domain.model.dto;

import es.in2.issuer.backend.signing.domain.model.SigningType;
import lombok.Builder;

/**
 * Signing request carried along the QTSP client chain.
 * {@code remoteSignature} is the tenant-resolved QTSP configuration
 * ({@link RemoteSignatureDto}) — set by {@link
 * es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider}
 * after reading from {@code tenant_signing_config}. All downstream components
 * (QtspAuthClient, QtspSignHashClient, QtspIssuerService, RemoteSignatureService)
 * read the tenant's QTSP from this field instead of a global configuration.
 */
@Builder
public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context,
        String typ,
        RemoteSignatureDto remoteSignature
) {}