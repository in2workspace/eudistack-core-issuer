package es.in2.issuer.backend.statuslist.application.policies.impl;

import es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequirePowerRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final PolicyContextFactory policyContextFactory;

    @Override
    public Mono<Void> validateRevokeCredential(String processId,
                                               String token,
                                               CredentialProcedure procedure) {

        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            log.info("Process ID: {} - Validating 'revoke' action...", processId);
            return validateStatus(procedure.getCredentialStatus())
                    .then(Mono.defer(() -> policyContextFactory.fromTokenSimple(token, tenantDomain)))
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, null).thenReturn(ctx))
                    .flatMap(ctx ->
                            RequirePowerRule.<Void>of("Onboarding", "Execute")
                                    .evaluate(ctx, null)
                                    .then(new RequireOrganizationRule()
                                            .evaluate(ctx, procedure.getOrganizationIdentifier()))
                    );
        });
    }

    @Override
    public Mono<Void> validateRevokeCredentialSystem(String processId, CredentialProcedure procedure) {
        return Mono.defer(() -> {
            log.info("Process ID: {} - Validating 'revoke' action (system)...", processId);
            return validateStatus(procedure.getCredentialStatus());
        });
    }

    private Mono<Void> validateStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus == VALID) {
            return Mono.empty();
        }
        return Mono.error(
                new InvalidStatusException("Invalid status: " + credentialStatus)
        );
    }
}
