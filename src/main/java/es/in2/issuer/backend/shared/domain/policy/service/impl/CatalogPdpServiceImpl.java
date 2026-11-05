package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.policy.service.CatalogPdpService;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.CHANGE_CATALOG;
import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Reads of the catalog are open to every role that can read it ({@link AuthorizationContext#canReadCredentialCatalog()})
 * of the token's own tenant. Writes are action {@code K2} of the authorization matrix, decided by
 * {@link PowerAuthorizationService}: the tenant administrator ({@code organization · <tenant> · Onboarding · Execute})
 * or the platform administrator acting as one, never from the {@code platform} tenant, which only reads. The
 * decision is traced as {@code authorization.permit} or {@code authorization.deny}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CatalogPdpServiceImpl implements CatalogPdpService {

    static final String DENY_DETAIL = "Only the tenant administrator can modify the attestation catalog";

    private static final String AUDIT_EVENT_AUTHZ_DENY = "authorization.deny";
    private static final String AUDIT_EVENT_TENANT_BREACH = "tenant_isolation_breach";
    private static final String ACTION_READ_CATALOG = "read_catalog";
    static final String READ_DENY_DETAIL = "Tenant administrator, SysAdmin or operator role required";

    private final AccessTokenService accessTokenService;
    private final PowerAuthorizationService powerAuthorizationService;
    private final AuditService auditService;

    @Override
    public Mono<AuthorizationContext> authorizeRead(String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(authCtx -> {
                    if (!authCtx.canReadCredentialCatalog()) {
                        // USER (EUD-253 point 6): an attestation of the tenant without administration
                        // powers. Audited like any other denial.
                        return Mono.deferContextual(reactorCtx -> {
                            auditService.auditFailure(AUDIT_EVENT_AUTHZ_DENY, authCtx.organizationIdentifier(),
                                    "role_not_permitted",
                                    Map.of("tenant", reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT),
                                            "action", ACTION_READ_CATALOG));
                            return Mono.<AuthorizationContext>error(new InsufficientPermissionException(READ_DENY_DETAIL));
                        });
                    }
                    return requireTenantMatch(authCtx, authorizationHeader);
                });
    }

    private Mono<AuthorizationContext> requireTenantMatch(AuthorizationContext authCtx, String authorizationHeader) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
            return accessTokenService.getTokenTenant(authorizationHeader)
                    .defaultIfEmpty("")
                    .flatMap(tokenTenant -> {
                        if (tokenTenant.isBlank() || !tokenTenant.equalsIgnoreCase(tenantDomain)) {
                            auditService.auditFailure(AUDIT_EVENT_TENANT_BREACH, authCtx.organizationIdentifier(),
                                    "token_tenant_mismatch",
                                    Map.of("tokenTenant", tokenTenant, "resolvedTenant", tenantDomain));
                            return Mono.<AuthorizationContext>error(new TenantMismatchException(
                                    "Token tenant '" + tokenTenant + "' does not match tenant header '" + tenantDomain + "'"));
                        }
                        return Mono.just(authCtx);
                    });
        });
    }

    /**
     * {@code K2}. A token of another tenant fails as {@code TenantMismatchException}; any other denial (a role the
     * matrix does not allow, the read-only {@code platform} tenant) as {@code InsufficientPermissionException}, the
     * {@code insufficient_permission} of the catalog contract.
     */
    @Override
    public Mono<AuthorizationContext> authorizeWrite(String authorizationHeader) {
        return powerAuthorizationService.authorize(CHANGE_CATALOG, null, null)
                .onErrorMap(LearIssuancePolicyException.class, e -> new InsufficientPermissionException(DENY_DETAIL))
                .then(Mono.defer(() -> accessTokenService.getAuthorizationContext(authorizationHeader)));
    }
}
