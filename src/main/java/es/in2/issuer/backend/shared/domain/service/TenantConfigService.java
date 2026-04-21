package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

/**
 * Reads per-tenant configuration from the tenant_config table in the
 * current tenant's schema (resolved via search_path).
 *
 * <p>Keys use service prefix convention: {@code issuer.wallet_url},
 * {@code issuer.default_lang}, {@code verifier.login_timeout}, etc.
 */
public interface TenantConfigService {

    /**
     * Returns the config value for the given key, or empty if not found.
     */
    Mono<String> getString(String key);

    /**
     * Returns the config value for the given key, or the default if not found.
     */
    Mono<String> getStringOrDefault(String key, String defaultValue);

}
