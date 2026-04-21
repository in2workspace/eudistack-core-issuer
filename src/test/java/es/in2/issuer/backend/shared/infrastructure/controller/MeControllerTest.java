package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.MeResponse;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MeControllerTest {

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private MeController meController;

    @Test
    void getMe_returnsAuthorizationContextAndTenant() {
        String authHeader = "Bearer token";
        AuthorizationContext auth = new AuthorizationContext(
                "VATES-A78446333", UserRole.TENANT_ADMIN, false);
        when(accessTokenService.getAuthorizationContext(authHeader)).thenReturn(Mono.just(auth));

        Mono<MeResponse> result = meController.getMe(authHeader)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg"));

        StepVerifier.create(result)
                .expectNext(new MeResponse(
                        "VATES-A78446333",
                        UserRole.TENANT_ADMIN,
                        false,
                        "kpmg"))
                .verifyComplete();
    }

    @Test
    void getMe_readonlySysAdminOnPlatform() {
        String authHeader = "Bearer token";
        AuthorizationContext auth = new AuthorizationContext(
                "VATES-A15456585", UserRole.SYSADMIN, true);
        when(accessTokenService.getAuthorizationContext(authHeader)).thenReturn(Mono.just(auth));

        Mono<MeResponse> result = meController.getMe(authHeader)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "platform"));

        StepVerifier.create(result)
                .expectNext(new MeResponse(
                        "VATES-A15456585",
                        UserRole.SYSADMIN,
                        true,
                        "platform"))
                .verifyComplete();
    }
}
