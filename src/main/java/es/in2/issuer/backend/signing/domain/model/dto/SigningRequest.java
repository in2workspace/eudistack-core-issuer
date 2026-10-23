package es.in2.issuer.backend.signing.domain.model.dto;

import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.infrastructure.adapter.impl.DelegatingSigningProviderImpl;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import lombok.Builder;

/**
 * Signing request carried along the QTSP client chain.
 * {@code remoteSignature} is the tenant-resolved QTSP configuration
 * ({@link RemoteSignatureDto}) — set by {@link
 * DelegatingSigningProviderImpl}
 * after reading from {@code tenant_signing_config}. All downstream components
 * (CscPortRouter, IssuerCertificateService, SignDocService)
 * read the tenant's QTSP config from this field instead of a global configuration.
 * {@code ownKey} is the same for the own-key modality (EUD-289): set by
 * {@link DelegatingSigningProviderImpl} and read by the KMS provider.
 */
@Builder
public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context,
        String typ,
        RemoteSignatureDto remoteSignature,
        OwnKeySigningConfig ownKey
) {}
