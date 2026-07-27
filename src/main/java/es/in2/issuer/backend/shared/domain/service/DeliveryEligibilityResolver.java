package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.EnumSet;
import java.util.Set;

/**
 * Resolves which delivery modes are eligible for a {@code credential_configuration_id},
 * combining the tenant's explicit configuration (or the AD-3 permissive default when
 * absent) with the base {@code cnfRequired} rule, which always excludes {@link DeliveryMode#DIRECT}
 * for types requiring cryptographic binding — configuration never overrides that rule.
 */
@Service
@RequiredArgsConstructor
public class DeliveryEligibilityResolver {

    private final TenantDeliveryConfigService tenantDeliveryConfigService;
    private final CredentialProfileRegistry credentialProfileRegistry;

    /**
     * The tenant's configured modes, or every mode when no explicit configuration
     * exists (AD-3). Does not apply the {@code cnfRequired} rule — this reflects what
     * the tenant admin configured (or the default), not the final emission-time semantics.
     */
    public Mono<Set<DeliveryMode>> getEligibleModes(String credentialConfigurationId) {
        return tenantDeliveryConfigService.getEligibleModes(credentialConfigurationId)
                .defaultIfEmpty(EnumSet.allOf(DeliveryMode.class));
    }

    public Mono<Boolean> isEligible(String credentialConfigurationId, Set<DeliveryMode> requestedModes) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        return getEligibleModes(credentialConfigurationId)
                .map(configured -> applyCnfRule(configured, profile.cnfRequired()))
                .map(base -> base.containsAll(requestedModes));
    }

    private Set<DeliveryMode> applyCnfRule(Set<DeliveryMode> configured, boolean cnfRequired) {
        if (!cnfRequired) {
            return configured;
        }
        Set<DeliveryMode> base = EnumSet.copyOf(configured);
        base.remove(DeliveryMode.DIRECT);
        return base;
    }

}
