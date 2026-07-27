package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Manages the delivery modes a tenant admin has made eligible for a given
 * {@code credential_configuration_id}, backed by {@code tenant_config}
 * (key {@code issuer.delivery.eligible_modes.<configId>}).
 *
 * <p>Reads and writes go straight to the repository (no caching): the value
 * is consulted on every issuance, so a cached read could serve a stale
 * eligibility decision after a tenant admin updates the policy.
 */
public interface TenantDeliveryConfigService {

    /**
     * Empty result means no explicit configuration exists for this
     * {@code credentialConfigurationId} (caller applies its own default).
     * An I/O failure surfaces as an error, never as empty.
     */
    Mono<Set<DeliveryMode>> getEligibleModes(String credentialConfigurationId);

    /**
     * Replaces the full set of eligible modes for this
     * {@code credentialConfigurationId} (no merge with any previous value).
     */
    Mono<Void> setEligibleModes(String credentialConfigurationId, Set<DeliveryMode> modes);

}
