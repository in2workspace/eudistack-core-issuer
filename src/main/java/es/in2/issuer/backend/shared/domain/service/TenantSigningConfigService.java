package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import reactor.core.publisher.Mono;

/**
 * Resolves signing configuration for the current tenant from the
 * {@code tenant_signing_config} table (via search_path). No global fallback:
 * tenants without an active row will cause a downstream signing error.
 */
public interface TenantSigningConfigService {

    /**
     * Returns the active signing configuration (QTSP or own key) of the current tenant, or
     * {@code Mono.empty()} if the tenant has no active row in {@code tenant_signing_config}.
     * Fails with a {@code SigningException} (reason {@code NO_CONFIGURATION}) when the active
     * row is corrupt.
     *
     * <p>Within a {@code SigningConfigScope}, every read after the first returns the configuration of
     * the first one (EUD-289 M4).
     */
    Mono<ActiveSigningConfig> getActiveSigningConfig();

    /**
     * Like {@link #getActiveSigningConfig()}, but discards this instance's cached configuration of the
     * current tenant first, so the row is read again. For a cached configuration that has stopped
     * working, e.g. an own key disabled in KMS when it was replaced or withdrawn (EUD-289 D-3).
     *
     * <p>Within a {@code SigningConfigScope}, if the row read again differs from the configuration the
     * request already used, it fails with {@code SigningConfigurationChangedException} and the scope
     * runs the request again.
     */
    Mono<ActiveSigningConfig> reloadActiveSigningConfig();

}
