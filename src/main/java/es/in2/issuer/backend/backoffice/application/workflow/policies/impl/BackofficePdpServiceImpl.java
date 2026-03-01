package es.in2.issuer.backend.backoffice.application.workflow.policies.impl;

import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequirePowerRule;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Service
@Slf4j
@RequiredArgsConstructor
public class BackofficePdpServiceImpl implements BackofficePdpService {

    private final PolicyContextFactory policyContextFactory;
    private final PolicyEnforcer policyEnforcer;
    private final CredentialProcedureRepository credentialProcedureRepository;

    @Override
    public Mono<Void> validateSignCredential(String processId, String token, String credentialProcedureId) {
        log.info("Validating 'sign' action for processId={} and credentialProcedureId={}", processId, credentialProcedureId);
        return validateCommon(token, credentialProcedureId);
    }

    @Override
    public Mono<Void> validateSendReminder(String processId, String token, String credentialProcedureId) {
        log.info("Validating 'send reminder' action for processId={} and credentialProcedureId={}", processId, credentialProcedureId);
        return validateCommon(token, credentialProcedureId);
    }

    private Mono<Void> validateCommon(String token, String credentialProcedureId) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            return policyContextFactory.fromTokenSimple(token, tenantDomain)
                    .flatMap(ctx ->
                            policyEnforcer.enforce(ctx, null, RequirePowerRule.of("Onboarding", "Execute"))
                                    .then(Mono.defer(() -> {
                                        // Performance: skip DB lookup for sysAdmin. RequireOrganizationRule
                                        // would also pass, but only after the findById roundtrip.
                                        if (ctx.sysAdmin()) {
                                            log.info("User belongs to admin organization. Skipping DB lookup.");
                                            return Mono.empty();
                                        }
                                        return credentialProcedureRepository.findById(UUID.fromString(credentialProcedureId))
                                                .flatMap(proc -> new RequireOrganizationRule()
                                                        .evaluate(ctx, proc.getOrganizationIdentifier()));
                                    }))
                    );
        });
    }
}
