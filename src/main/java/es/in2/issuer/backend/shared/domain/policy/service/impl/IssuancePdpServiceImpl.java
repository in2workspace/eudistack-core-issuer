package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
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

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class IssuancePdpServiceImpl implements IssuancePdpService {

    private final PolicyContextFactory policyContextFactory;
    private final ObjectMapper objectMapper;
    private final RequireCertificationIssuanceRule requireCertificationIssuanceRule;
    private final RequireCredentialProfileAllowedForTenantRule requireCredentialProfileAllowedForTenantRule;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final DynamicCredentialParser credentialParser;
    private final AuditService auditService;
    private final TenantConfigService tenantConfigService;

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

    private Mono<Void> evaluateIssuancePolicy(CredentialProfile profile, es.in2.issuer.backend.shared.domain.policy.PolicyContext ctx, JsonNode payload, String idToken) {
        CredentialProfile.IssuancePolicy issuancePolicy = profile.issuancePolicy();
        if (issuancePolicy == null || issuancePolicy.rules() == null || issuancePolicy.rules().isEmpty()) {
            return Mono.error(new InsufficientPermissionException(
                    "Unauthorized: No issuance policy defined for " + profile.credentialConfigurationId()));
        }

        List<String> ruleNames = issuancePolicy.rules();
        if (ruleNames.size() != 1) {
            return Mono.error(new InsufficientPermissionException(
                    "Unauthorized: issuance_policy.rules must contain exactly one rule (got "
                            + ruleNames.size() + ") for " + profile.credentialConfigurationId()));
        }

        String ruleName = ruleNames.get(0);
        return switch (ruleName) {
            case "RequireLearCredentialIssuance" ->
                    new RequireLearCredentialIssuanceRule(objectMapper, tenantConfigService).evaluate(ctx, payload);
            case "RequireCertificationIssuance" ->
                    requireCertificationIssuanceRule.evaluate(ctx, idToken);
            default -> Mono.error(new InsufficientPermissionException(
                    "Unauthorized: Unknown policy rule: " + ruleName));
        };
    }

    private Mono<String> getTokenFromSecurityContext() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> {
                    JwtAuthenticationToken auth = (JwtAuthenticationToken) ctx.getAuthentication();
                    return auth.getToken().getTokenValue();
                });
    }
}
