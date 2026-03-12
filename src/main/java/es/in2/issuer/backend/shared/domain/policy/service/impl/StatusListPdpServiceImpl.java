package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequirePowerRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireValidStatusRule;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final PolicyContextFactory policyContextFactory;

    @Override
    public Mono<Void> validateRevokeCredential(String processId,
                                               String token,
                                               Issuance issuance) {

        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            log.info("Process ID: {} - Validating 'revoke' action...", processId);
            return new RequireValidStatusRule().evaluate(null, issuance.getCredentialStatus())
                    .then(Mono.defer(() -> policyContextFactory.fromTokenSimple(token, tenantDomain)))
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, null).thenReturn(ctx))
                    .flatMap(ctx ->
                            RequirePowerRule.<Void>of("Onboarding", "Execute")
                                    .evaluate(ctx, null)
                                    .then(new RequireOrganizationRule()
                                            .evaluate(ctx, issuance.getOrganizationIdentifier()))
                    );
        });
    }

    @Override
    public Mono<Void> validateRevokeCredentialSystem(String processId, Issuance issuance) {
        return Mono.defer(() -> {
            log.info("Process ID: {} - Validating 'revoke' action (system)...", processId);
            return new RequireValidStatusRule().evaluate(null, issuance.getCredentialStatus());
        });
    }
}
