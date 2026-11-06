package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import reactor.core.publisher.Mono;

/**
 * Resolves signing configuration for the current tenant: the active row of the
 * {@code tenant_signing_config} table (via search_path) and, for an own key, the certificate infra
 * publishes for the tenant. No global fallback: tenants without an active row will cause a
 * downstream signing error.
 */
public interface TenantSigningConfigService {

    /**
     * Returns the active signing configuration (QTSP or own key) of the current tenant, or
     * {@code Mono.empty()} if the tenant has no active row in {@code tenant_signing_config}.
     * Fails with a {@code SigningException} (reason {@code NO_CONFIGURATION}) when the active
     * row is corrupt; for an own key, also with the reasons of {@code OwnKeySigningConfigLoader}.
     *
     * <p>Within a {@code SigningConfigScope}, every read after the first returns the configuration of
     * the first one.
     */
    Mono<ActiveSigningConfig> getActiveSigningConfig();

    /**
     * Like {@link #getActiveSigningConfig()}, but discards this instance's cached configuration of the
     * current tenant first, so the row and, for an own key, its certificate are read again. For a
     * cached configuration that has stopped working, e.g. an own key that KMS no longer lets sign.
     *
     * <p>Within a {@code SigningConfigScope}, if the configuration read again differs from the one the
     * request already used, it fails with {@code SigningConfigurationChangedException} and the scope
     * runs the request again.
     */
    Mono<ActiveSigningConfig> reloadActiveSigningConfig();

}
