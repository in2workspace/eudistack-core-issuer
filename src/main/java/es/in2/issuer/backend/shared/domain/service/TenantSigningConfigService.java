package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import reactor.core.publisher.Mono;

/**
 * Resolves signing configuration for the current tenant.
 * Reads from tenant_signing_config table (via search_path).
 * Falls back to the global default QTSP (mock) if no tenant-specific config exists.
 */
public interface TenantSigningConfigService {

    /**
     * Returns the remote signature configuration for the current tenant.
     * Falls back to global default if tenant has no config.
     */
    Mono<RemoteSignatureDto> getRemoteSignature();

    /**
     * Returns the provider name for the current tenant.
     * Falls back to global default if tenant has no config.
     */
    Mono<String> getProvider();

}
