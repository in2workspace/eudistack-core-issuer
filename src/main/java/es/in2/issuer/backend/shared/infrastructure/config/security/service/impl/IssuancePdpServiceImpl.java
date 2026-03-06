package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.*;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.IssuancePdpService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
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
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final DynamicCredentialParser credentialParser;

    @Observed(name = "issuance.pdp-authorize", contextualName = "issuance-pdp-authorize")
    @Override
    public Mono<Void> authorize(String credentialConfigurationId, JsonNode payload, String idToken) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);

            // Resolve the logical credential type from the configuration ID so that
            // all format variants of the same type use the same authorization policy.
            CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
            String credentialType = profile != null ? profile.credentialType() : credentialConfigurationId;

            return getTokenFromSecurityContext()
                    .flatMap(token -> policyContextFactory.fromTokenForIssuance(token, credentialType, tenantDomain))
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, payload).thenReturn(ctx))
                    .flatMap(ctx -> switch (credentialType) {
                        case LEAR_CREDENTIAL_EMPLOYEE -> policyEnforcer.enforceAny(ctx, payload,
                                "Unauthorized: LEARCredentialEmployee does not meet any issuance policies.",
                                new RequireSignerIssuanceRule(),
                                new RequireMandatorDelegationRule("ProductOffering", objectMapper, credentialParser));
                        case LEAR_CREDENTIAL_MACHINE -> policyEnforcer.enforceAny(ctx, payload,
                                "Unauthorized: LEARCredentialMachine does not meet any issuance policies.",
                                new RequireSignerIssuanceRule(),
                                new RequireMandatorDelegationRule("Onboarding", objectMapper, credentialParser));
                        case LABEL_CREDENTIAL -> requireCertificationIssuanceRule.evaluate(ctx, idToken);
                        default -> Mono.error(new InsufficientPermissionException(
                                "Unauthorized: Unsupported schema"));
                    });
        });
    }

    private Mono<String> getTokenFromSecurityContext() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> {
                    JwtAuthenticationToken auth = (JwtAuthenticationToken) ctx.getAuthentication();
                    return auth.getToken().getTokenValue();
                });
    }
}
