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
 * for display on the TenantAdmin-facing {@code GET} endpoint.
 *
 * <p>The actual issuance-time enforcement (including the hard rule that
 * {@code cnfRequired} credential types always exclude {@link DeliveryMode#DIRECT},
 * regardless of tenant configuration) lives in
 * {@code IssuanceWorkflowImpl#resolveAndValidateDeliveryModes} (EUD-167). The default
 * applied here when no explicit configuration exists mirrors that same rule, so the
 * admin view never shows a mode as eligible that issuance would in fact reject.
 */
@Service
@RequiredArgsConstructor
public class DeliveryEligibilityResolver {

    private final TenantDeliveryConfigService tenantDeliveryConfigService;
    private final CredentialProfileRegistry credentialProfileRegistry;

    public Mono<Set<DeliveryMode>> getEligibleModes(String credentialConfigurationId) {
        return tenantDeliveryConfigService.getEligibleModes(credentialConfigurationId)
                .switchIfEmpty(Mono.fromSupplier(() -> defaultModesFor(credentialConfigurationId)));
    }

    private Set<DeliveryMode> defaultModesFor(String credentialConfigurationId) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        boolean cnfRequired = profile != null && profile.cnfRequired();
        return cnfRequired
                ? EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI)
                : EnumSet.allOf(DeliveryMode.class);
    }

}
