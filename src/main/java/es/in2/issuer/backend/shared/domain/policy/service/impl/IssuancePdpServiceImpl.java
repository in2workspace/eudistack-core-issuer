package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import es.in2.issuer.backend.shared.domain.policy.rules.*;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class IssuancePdpServiceImpl implements IssuancePdpService {

    private final PolicyContextFactory policyContextFactory;
    private final PolicyEnforcer policyEnforcer;
    private final ObjectMapper objectMapper;
    private final RequireCertificationIssuanceRule requireCertificationIssuanceRule;
    private final RequireCredentialProfileAllowedForTenantRule requireCredentialProfileAllowedForTenantRule;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final DynamicCredentialParser credentialParser;
    private final AuditService auditService;

    @Observed(name = "issuance.pdp-authorize", contextualName = "issuance-pdp-authorize")
    @Override
    public Mono<Void> authorize(String credentialConfigurationId, JsonNode payload, String idToken) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);

            CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
            if (profile == null) {
                return Mono.error(new InsufficientPermissionException(
                        "Unauthorized: No profile found for " + credentialConfigurationId));
            }

            return getTokenFromSecurityContext()
                    .flatMap(token -> policyContextFactory.fromTokenForIssuance(token, credentialConfigurationId, tenantDomain))
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, payload).thenReturn(ctx))
                    .flatMap(ctx -> requireCredentialProfileAllowedForTenantRule.evaluate(ctx, credentialConfigurationId).thenReturn(ctx))
                    .flatMap(ctx -> {
                        Mono<Void> decision = evaluateIssuancePolicy(profile, ctx, payload, idToken);
                        return decision
                                .doOnSuccess(v -> auditService.auditSuccess("authorization.permit",
                                        ctx.organizationIdentifier(), "issuance", credentialConfigurationId, java.util.Map.of()))
                                .doOnError(e -> auditService.auditFailure("authorization.deny",
                                        ctx.organizationIdentifier(), e.getMessage(), java.util.Map.of("credentialType", credentialConfigurationId)));
                    });
        });
    }

    @SuppressWarnings("unchecked")
    private Mono<Void> evaluateIssuancePolicy(CredentialProfile profile, es.in2.issuer.backend.shared.domain.policy.PolicyContext ctx, JsonNode payload, String idToken) {
        CredentialProfile.IssuancePolicy issuancePolicy = profile.issuancePolicy();
        if (issuancePolicy == null || issuancePolicy.rules() == null || issuancePolicy.rules().isEmpty()) {
            return Mono.error(new InsufficientPermissionException(
                    "Unauthorized: No issuance policy defined for " + profile.credentialConfigurationId()));
        }

        List<PolicyRule<JsonNode>> rules = new ArrayList<>();
        for (String ruleName : issuancePolicy.rules()) {
            switch (ruleName) {
                case "RequireSignerIssuance" -> rules.add(new RequireSignerIssuanceRule());
                case "RequireMandatorDelegation" -> {
                    String delegationFunction = issuancePolicy.delegationFunction();
                    rules.add(new RequireMandatorDelegationRule(delegationFunction, objectMapper, credentialParser));
                }
                case "RequireCertificationIssuance" ->
                    // This rule uses String (idToken) as target, not JsonNode — evaluate it separately
                    { return requireCertificationIssuanceRule.evaluate(ctx, idToken); }
                default -> { return Mono.error(new InsufficientPermissionException(
                        "Unauthorized: Unknown policy rule: " + ruleName)); }
            }
        }

        String failureMessage = "Unauthorized: " + profile.credentialConfigurationId() + " does not meet any issuance policies.";
        return policyEnforcer.enforceAny(ctx, payload, failureMessage, rules.toArray(new PolicyRule[0]));
    }

    private Mono<String> getTokenFromSecurityContext() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> {
                    JwtAuthenticationToken auth = (JwtAuthenticationToken) ctx.getAuthentication();
                    return auth.getToken().getTokenValue();
                });
    }
}
