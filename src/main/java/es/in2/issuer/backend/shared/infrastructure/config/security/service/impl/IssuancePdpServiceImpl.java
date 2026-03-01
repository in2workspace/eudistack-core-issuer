package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCertificationIssuanceRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireMandatorEmployeeIssuanceRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireMandatorMachineIssuanceRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireSignerIssuanceRule;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.IssuancePdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class IssuancePdpServiceImpl implements IssuancePdpService {

    private final PolicyContextFactory policyContextFactory;
    private final PolicyEnforcer policyEnforcer;
    private final ObjectMapper objectMapper;
    private final RequireCertificationIssuanceRule requireCertificationIssuanceRule;

    @Override
    public Mono<Void> authorize(String token, String schema, JsonNode payload, String idToken) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            return policyContextFactory.fromTokenForIssuance(token, schema, tenantDomain)
                    .flatMap(ctx -> switch (schema) {
                        case LEAR_CREDENTIAL_EMPLOYEE -> policyEnforcer.enforceAny(ctx, payload,
                                "Unauthorized: LEARCredentialEmployee does not meet any issuance policies.",
                                new RequireSignerIssuanceRule(),
                                new RequireMandatorEmployeeIssuanceRule(objectMapper));
                        case LEAR_CREDENTIAL_MACHINE -> policyEnforcer.enforceAny(ctx, payload,
                                "Unauthorized: LEARCredentialMachine does not meet any issuance policies.",
                                new RequireSignerIssuanceRule(),
                                new RequireMandatorMachineIssuanceRule(objectMapper));
                        case LABEL_CREDENTIAL -> requireCertificationIssuanceRule.evaluate(ctx, idToken);
                        default -> Mono.error(new InsufficientPermissionException(
                                "Unauthorized: Unsupported schema"));
                    });
        });
    }
}
