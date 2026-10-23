package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule;
import es.in2.issuer.backend.shared.domain.policy.service.CatalogPdpService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Reads of the catalog are open to every role that can read it ({@link AuthorizationContext#canReadCredentialCatalog()})
 * of the token's own tenant. Writes to the catalog belong to the tenant's administrator: the administrator organization
 * ({@code admin_organization_id}) holding Onboarding/Execute over the tenant's domain
 * ({@link PolicyContext#tenantAdmin()}), or a SysAdmin. A SysAdmin on the {@code platform}
 * tenant only has a read-only view, so {@link AuthorizationContext#canWrite()} must hold too.
 *
 * <p>Deliberately not {@code RequirePowerRule}: it does not check the administrator
 * organization and denies with {@code unauthorized_role}, which the catalog contract does not use.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CatalogPdpServiceImpl implements CatalogPdpService {

    static final String DENY_DETAIL = "Only the tenant administrator can modify the attestation catalog";

    private static final String AUDIT_EVENT_AUTHZ_DENY = "authorization.deny";
    private static final String AUDIT_EVENT_TENANT_BREACH = "tenant_isolation_breach";
    private static final String ACTION_WRITE_CATALOG = "write_catalog";
    private static final String ACTION_READ_CATALOG = "read_catalog";
    static final String READ_DENY_DETAIL = "Tenant administrator, SysAdmin or operator role required";

    private final AccessTokenService accessTokenService;
    private final PolicyContextFactory policyContextFactory;
    private final AuditService auditService;

    @Override
    public Mono<AuthorizationContext> authorizeRead(String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(authCtx -> {
                    if (!authCtx.canReadCredentialCatalog()) {
                        // Unreachable today: UserRole has exactly three values and all of them can read
                        // (see AuthorizationContext#canReadCredentialCatalog). Audited so the denial of a
                        // future fourth role is not silently invisible.
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

    @Override
    public Mono<AuthorizationContext> authorizeWrite(String authorizationHeader) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            return accessTokenService.getAuthorizationContext(authorizationHeader)
                    .flatMap(authCtx -> accessTokenService.getCleanBearerToken(authorizationHeader)
                            .flatMap(token -> policyContextFactory.fromManagementToken(token, tenantDomain))
                            .flatMap(policyCtx -> decide(authCtx, policyCtx)));
        });
    }

    private Mono<AuthorizationContext> decide(AuthorizationContext authCtx, PolicyContext policyCtx) {
        // Tenant first: a token of another tenant never resolves as administrator here (its power
        // carries the other tenant's domain), so checking the role first would hide the mismatch.
        return new RequireTenantMatchRule().evaluate(policyCtx, null)
                .doOnError(TenantMismatchException.class, e -> auditService.auditFailure(
                        AUDIT_EVENT_TENANT_BREACH, authCtx.organizationIdentifier(), "token_tenant_mismatch",
                        Map.of("tokenTenant", String.valueOf(policyCtx.tokenTenant()),
                                "resolvedTenant", String.valueOf(policyCtx.tenantDomain()))))
                .then(Mono.defer(() -> requireAdministratorWithWriteAccess(authCtx, policyCtx)));
    }

    private Mono<AuthorizationContext> requireAdministratorWithWriteAccess(AuthorizationContext authCtx,
                                                                         PolicyContext policyCtx) {
        boolean administrator = policyCtx.sysAdmin() || policyCtx.tenantAdmin();
        if (!administrator || !authCtx.canWrite()) {
            auditService.auditFailure(AUDIT_EVENT_AUTHZ_DENY, authCtx.organizationIdentifier(),
                    "role_not_permitted",
                    Map.of("tenant", String.valueOf(policyCtx.tenantDomain()), "action", ACTION_WRITE_CATALOG));
            return Mono.error(new InsufficientPermissionException(DENY_DETAIL));
        }
        return Mono.just(authCtx);
    }
}
