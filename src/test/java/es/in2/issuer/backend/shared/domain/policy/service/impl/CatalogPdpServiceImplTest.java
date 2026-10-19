package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CatalogPdpServiceImplTest {

    private static final String HEADER = "Bearer token";
    private static final String TOKEN = "token";
    private static final String TENANT = "tenant-a";
    private static final String ORG = "org-1";

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private PolicyContextFactory policyContextFactory;

    @Mock
    private AuditService auditService;

    private CatalogPdpServiceImpl pdp;

    @BeforeEach
    void setUp() {
        pdp = new CatalogPdpServiceImpl(accessTokenService, policyContextFactory, auditService);
        when(accessTokenService.getCleanBearerToken(HEADER)).thenReturn(Mono.just(TOKEN));
    }

    @Test
    void authorizeWrite_tenantAdmin_returnsAuthorizationContext() {
        AuthorizationContext authCtx = authorization(UserRole.TENANT_ADMIN, false);
        givenContexts(authCtx, policy(false, true, TENANT));

        StepVerifier.create(authorize())
                .expectNext(authCtx)
                .verifyComplete();
    }

    @Test
    void authorizeWrite_sysAdminOutsidePlatform_isAllowed() {
        AuthorizationContext authCtx = authorization(UserRole.SYSADMIN, false);
        givenContexts(authCtx, policy(true, false, TENANT));

        StepVerifier.create(authorize())
                .expectNext(authCtx)
                .verifyComplete();
    }

    @Test
    void authorizeWrite_operator_failsWithInsufficientPermissionAndAuditsDeny() {
        givenContexts(authorization(UserRole.LEAR, false), policy(false, false, TENANT));

        StepVerifier.create(authorize())
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessage(CatalogPdpServiceImpl.DENY_DETAIL))
                .verify();

        verify(auditService).auditFailure(eq("authorization.deny"), eq(ORG), anyString(), any());
    }

    @Test
    void authorizeWrite_organizationWithPowerButNotAdminOrganization_isDenied() {
        // Onboarding/Execute over the tenant's domain, but organization != admin_organization_id:
        // PolicyContextFactory resolves tenantAdmin=false, and AccessTokenService resolves LEAR.
        givenContexts(authorization(UserRole.LEAR, false), policy(false, false, TENANT));

        StepVerifier.create(authorize())
                .expectError(InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void authorizeWrite_adminOrganizationWithPowerOnAnotherDomain_isDenied() {
        // AccessTokenService does not check the power's domain and says TENANT_ADMIN;
        // the PDP does (PolicyContext.tenantAdmin requires domain == tenant).
        givenContexts(authorization(UserRole.TENANT_ADMIN, false), policy(false, false, TENANT));

        StepVerifier.create(authorize())
                .expectError(InsufficientPermissionException.class)
                .verify();
        verify(auditService).auditFailure(eq("authorization.deny"), eq(ORG), anyString(), any());
    }

    @Test
    void authorizeWrite_sysAdminReadOnlyView_isDenied() {
        givenContexts(authorization(UserRole.SYSADMIN, true), policy(true, false, TENANT));

        StepVerifier.create(authorize())
                .expectError(InsufficientPermissionException.class)
                .verify();
        verify(auditService).auditFailure(eq("authorization.deny"), eq(ORG), anyString(), any());
    }

    @Test
    void authorizeWrite_tokenOfAnotherTenant_failsWithTenantMismatchAndAuditsBreach() {
        givenContexts(authorization(UserRole.TENANT_ADMIN, false), policy(false, true, "tenant-b"));

        StepVerifier.create(authorize())
                .expectError(TenantMismatchException.class)
                .verify();

        verify(auditService).auditFailure(eq("tenant_isolation_breach"), eq(ORG), anyString(), any());
        verify(auditService, never()).auditFailure(eq("authorization.deny"), anyString(), anyString(), any());
    }

    @Test
    void authorizeWrite_sysAdminWithTokenOfAnotherTenant_failsWithTenantMismatch() {
        givenContexts(authorization(UserRole.SYSADMIN, false), policy(true, false, "tenant-b"));

        StepVerifier.create(authorize())
                .expectError(TenantMismatchException.class)
                .verify();
    }

    @Test
    void authorizeWrite_operatorWithTokenOfAnotherTenant_failsWithTenantMismatch() {
        givenContexts(authorization(UserRole.LEAR, false), policy(false, false, "tenant-b"));

        StepVerifier.create(authorize())
                .expectError(TenantMismatchException.class)
                .verify();
    }

    @Test
    void authorizeWrite_neverFailsWithUnauthorizedRole() {
        givenContexts(authorization(UserRole.LEAR, false), policy(false, false, TENANT));

        StepVerifier.create(authorize())
                .expectErrorSatisfies(e -> assertThat(e).isNotInstanceOf(UnauthorizedRoleException.class))
                .verify();
    }

    private Mono<AuthorizationContext> authorize() {
        return pdp.authorizeWrite(HEADER)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private void givenContexts(AuthorizationContext authCtx, PolicyContext policyCtx) {
        when(accessTokenService.getAuthorizationContext(HEADER)).thenReturn(Mono.just(authCtx));
        when(policyContextFactory.fromManagementToken(TOKEN, TENANT)).thenReturn(Mono.just(policyCtx));
    }

    private static AuthorizationContext authorization(UserRole role, boolean readOnly) {
        return new AuthorizationContext(ORG, role, readOnly, PolicyContext.TENANT_TYPE_SIMPLE);
    }

    private static PolicyContext policy(boolean sysAdmin, boolean tenantAdmin, String tokenTenant) {
        return new PolicyContext(ORG, List.of(), null, null, null, sysAdmin, tenantAdmin, TENANT, tokenTenant,
                PolicyContext.TENANT_TYPE_SIMPLE);
    }
}
