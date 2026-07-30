package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Manages the delivery modes a tenant admin has made eligible for a given
 * {@code credential_configuration_id}, backed by {@code tenant_config}
 * (key {@code issuer.delivery.modes.<configId>}) — the same key
 * {@code IssuanceWorkflowImpl#resolveAndValidateDeliveryModes} reads at issuance time.
 *
 * <p>This port's own reads and writes go straight to the repository (no caching),
 * so the TenantAdmin-facing {@code GET} reflects a write immediately. The
 * issuance-time read goes through the generic, cached {@code TenantConfigService}
 * instead, so a policy change there is subject to that cache's TTL.
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
