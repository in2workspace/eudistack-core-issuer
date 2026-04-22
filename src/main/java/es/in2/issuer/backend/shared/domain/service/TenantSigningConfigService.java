package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import reactor.core.publisher.Mono;

/**
 * Resolves signing configuration for the current tenant from the
 * {@code tenant_signing_config} table (via search_path). No global fallback:
 * tenants without a row will cause a downstream signing error.
 */
public interface TenantSigningConfigService {

    /**
     * Returns the remote signature configuration for the current tenant,
     * or {@code Mono.empty()} if the tenant has no row in
     * {@code tenant_signing_config}.
     */
    Mono<RemoteSignatureDto> getRemoteSignature();

}
