package es.in2.issuer.backend.issuance.application.workflow.policies.impl;

import es.in2.issuer.backend.issuance.application.workflow.policies.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequirePowerRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Service
@Slf4j
@RequiredArgsConstructor
public class IssuancePdpServiceImpl implements IssuancePdpService {

    private final PolicyContextFactory policyContextFactory;
    private final PolicyEnforcer policyEnforcer;
    private final IssuanceRepository issuanceRepository;
    private final AuditService auditService;

    @Override
    public Mono<Void> validateSignCredential(String processId, String token, String issuanceId) {
        log.info("Validating 'sign' action for processId={} and issuanceId={}", processId, issuanceId);
        return validateCommon(token, issuanceId);
    }

    @Override
    public Mono<Void> validateSendReminder(String processId, String token, String issuanceId) {
        log.info("Validating 'send reminder' action for processId={} and issuanceId={}", processId, issuanceId);
        return validateCommon(token, issuanceId);
    }

    private Mono<Void> validateCommon(String token, String issuanceId) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            return policyContextFactory.fromTokenSimple(token, tenantDomain)
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, null).thenReturn(ctx))
                    .flatMap(ctx ->
                            policyEnforcer.enforce(ctx, null, RequirePowerRule.of("Onboarding", "Execute"))
                                    .then(Mono.defer(() -> {
                                        if (ctx.sysAdmin()) {
                                            log.info("User belongs to admin organization. Skipping DB lookup.");
                                            return Mono.empty();
                                        }
                                        return issuanceRepository.findById(UUID.fromString(issuanceId))
                                                .flatMap(proc -> new RequireOrganizationRule()
                                                        .evaluate(ctx, proc.getOrganizationIdentifier()));
                                    }))
                                    .doOnSuccess(v -> auditService.auditSuccess("authorization.permit",
                                            ctx.organizationIdentifier(), "issuance", issuanceId, java.util.Map.of()))
                                    .doOnError(e -> auditService.auditFailure("authorization.deny",
                                            ctx.organizationIdentifier(), e.getMessage(),
                                            java.util.Map.of("issuanceId", issuanceId)))
                    );
        });
    }
}
