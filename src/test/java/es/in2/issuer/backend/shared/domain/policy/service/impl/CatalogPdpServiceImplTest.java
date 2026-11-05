package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException.Reason;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CatalogPdpServiceImplTest {

    private static final String HEADER = "Bearer token";
    private static final String TENANT = "tenant-a";
    private static final String ORG = "org-1";

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private PowerAuthorizationService powerAuthorizationService;

    @Mock
    private AuditService auditService;

    private CatalogPdpServiceImpl pdp;

    @BeforeEach
    void setUp() {
        pdp = new CatalogPdpServiceImpl(accessTokenService, powerAuthorizationService, auditService);
    }

    @Test
    void authorizeRead_operatorOfTheTenant_returnsAuthorizationContext() {
        AuthorizationContext authCtx = authorization(UserRole.LEAR, false);
        givenReader(authCtx, TENANT);

        StepVerifier.create(authorizeRead())
                .expectNext(authCtx)
                .verifyComplete();
    }

    @Test
    void authorizeRead_sysAdminReadOnlyView_isAllowed() {
        AuthorizationContext authCtx = authorization(UserRole.SYSADMIN, true);
        givenReader(authCtx, TENANT);

        StepVerifier.create(authorizeRead())
                .expectNext(authCtx)
                .verifyComplete();
    }

    @Test
    void authorizeRead_tokenOfAnotherTenant_failsWithTenantMismatchAndAuditsBreach() {
        givenReader(authorization(UserRole.LEAR, false), "tenant-b");

        StepVerifier.create(authorizeRead())
                .expectError(TenantMismatchException.class)
                .verify();

        verify(auditService).auditFailure(eq("tenant_isolation_breach"), eq(ORG), anyString(), any());
    }

    @Test
    void authorizeRead_sysAdminWithTokenOfAnotherTenant_failsWithTenantMismatch() {
        givenReader(authorization(UserRole.SYSADMIN, true), "tenant-b");

        StepVerifier.create(authorizeRead())
                .expectError(TenantMismatchException.class)
                .verify();
    }

    @Test
    void authorizeRead_tokenWithoutTenantClaim_failsWithTenantMismatch() {
        when(accessTokenService.getAuthorizationContext(HEADER))
                .thenReturn(Mono.just(authorization(UserRole.LEAR, false)));
        when(accessTokenService.getTokenTenant(HEADER)).thenReturn(Mono.empty());

        StepVerifier.create(authorizeRead())
                .expectError(TenantMismatchException.class)
                .verify();
    }

    // ---- writes: K2 of the authorization matrix, decided by PowerAuthorizationService ----

    @Test
    void authorizeWrite_permittedByK2_returnsTheCallersAuthorizationContext() {
        AuthorizationContext authCtx = authorization(UserRole.TENANT_ADMIN, false);
        when(powerAuthorizationService.authorize(PowerAuthorizationService.CHANGE_CATALOG, null, null))
                .thenReturn(Mono.just(new AuthorizationDecision(PowerAuthorizationService.CHANGE_CATALOG, null, null)));
        when(accessTokenService.getAuthorizationContext(HEADER)).thenReturn(Mono.just(authCtx));

        StepVerifier.create(authorize())
                .expectNext(authCtx)
                .verifyComplete();
    }

    @Test
    void authorizeWrite_deniedByK2_failsWithInsufficientPermission() {
        givenK2Fails(new LearIssuancePolicyException(Reason.OPERATOR_LACKS_ONBOARDING, "denied"));

        StepVerifier.create(authorize())
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessage(CatalogPdpServiceImpl.DENY_DETAIL))
                .verify();
    }

    @Test
    void authorizeWrite_fromThePlatformTenant_failsWithInsufficientPermission() {
        givenK2Fails(new LearIssuancePolicyException(Reason.PLATFORM_TENANT_READ_ONLY, "read only"));

        StepVerifier.create(authorize())
                .expectError(InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void authorizeWrite_tokenOfAnotherTenant_keepsTheTenantMismatch() {
        givenK2Fails(new TenantMismatchException("Token tenant 'tenant-b' does not match tenant header 'tenant-a'"));

        StepVerifier.create(authorize())
                .expectError(TenantMismatchException.class)
                .verify();
    }

    /** The matrix traces the decision itself: the catalog adds no authorization event of its own. */
    @Test
    void authorizeWrite_denied_isNotAuditedTwice() {
        givenK2Fails(new LearIssuancePolicyException(Reason.OPERATOR_LACKS_ONBOARDING, "denied"));

        StepVerifier.create(authorize()).expectError().verify();

        verifyNoInteractions(auditService);
        verify(accessTokenService, never()).getAuthorizationContext(anyString());
    }

    private Mono<AuthorizationContext> authorizeRead() {
        return pdp.authorizeRead(HEADER)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private void givenReader(AuthorizationContext authCtx, String tokenTenant) {
        when(accessTokenService.getAuthorizationContext(HEADER)).thenReturn(Mono.just(authCtx));
        when(accessTokenService.getTokenTenant(HEADER)).thenReturn(Mono.just(tokenTenant));
    }

    private Mono<AuthorizationContext> authorize() {
        return pdp.authorizeWrite(HEADER)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private void givenK2Fails(Throwable error) {
        when(powerAuthorizationService.authorize(PowerAuthorizationService.CHANGE_CATALOG, null, null))
                .thenReturn(Mono.error(error));
    }

    private static AuthorizationContext authorization(UserRole role, boolean readOnly) {
        return new AuthorizationContext(ORG, role, readOnly, "simple");
    }
}
