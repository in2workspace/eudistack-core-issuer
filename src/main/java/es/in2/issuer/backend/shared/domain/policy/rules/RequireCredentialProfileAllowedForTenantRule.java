package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/**
 * PDP rule that verifies the requested credential type is enabled
 * for the current tenant. If the tenant has no configured profiles
 * (empty tenant_credential_profile table), all types are allowed.
 */
@Component
@RequiredArgsConstructor
public class RequireCredentialProfileAllowedForTenantRule implements PolicyRule<String> {

    private final TenantCredentialProfileService tenantCredentialProfileService;

    @Override
    public Mono<Void> evaluate(PolicyContext context, String credentialConfigurationId) {
        return tenantCredentialProfileService.isProfileAllowed(credentialConfigurationId)
                .flatMap(allowed -> {
                    if (Boolean.FALSE.equals(allowed)) {
                        return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN,
                                "Credential type '" + credentialConfigurationId +
                                "' is not enabled for this tenant"));
                    }
                    return Mono.empty();
                });
    }

}
