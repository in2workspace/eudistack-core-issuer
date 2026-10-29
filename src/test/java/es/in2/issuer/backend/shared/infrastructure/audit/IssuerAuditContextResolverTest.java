package es.in2.issuer.backend.shared.infrastructure.audit;

import com.eudistack.auditoria.domain.ActorKind;
import com.eudistack.auditoria.domain.AuditContext;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IssuerAuditContextResolverTest {

    private final AccessTokenService accessTokenService = mock(AccessTokenService.class);
    private final IssuerAuditContextResolver resolver = new IssuerAuditContextResolver(accessTokenService);
    private final MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/issuances").header(HttpHeaders.AUTHORIZATION, "Bearer token"));

    private static Authentication authentication(Map<String, Object> claims, String name) {
        Jwt jwt = new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "ES256"), claims);
        return new JwtAuthenticationToken(jwt, Collections.emptyList(), name);
    }

    private Mono<AuditContext> resolve(Authentication authentication) {
        return resolver.resolve(exchange, authentication)
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "sandbox"));
    }

    @Test
    void resolve_walletToken_isTheHolderOfTheIssuanceItNames() {
        // Arrange
        Authentication wallet = authentication(Map.of("sub", "wallet", "pid", "issuance-1"), "wallet");

        // Act & Assert
        StepVerifier.create(resolve(wallet))
                .assertNext(context -> {
                    assertEquals("sandbox", context.tenant());
                    assertEquals(ActorKind.HOLDER, context.actor().kind());
                    assertEquals("issuance-1", context.actor().id());
                })
                .verifyComplete();
    }

    @Test
    void resolve_machineToken_isASystemNamedByItsClient() {
        // Arrange
        Authentication machine = authentication(Map.of("sub", "machine", "client_id", "client-7"), "machine");
        when(accessTokenService.getOrganizationId("Bearer token")).thenReturn(Mono.just("VATES-A1"));

        // Act & Assert
        StepVerifier.create(resolve(machine))
                .assertNext(context -> {
                    assertEquals(ActorKind.SYSTEM, context.actor().kind());
                    assertEquals("client-7", context.actor().id());
                    assertEquals("VATES-A1", context.organization());
                })
                .verifyComplete();
    }

    @Test
    void resolve_userToken_isAPersonOfTheTokensOrganization() {
        // Arrange
        Authentication user = authentication(Map.of("sub", "user-1", "email", "jane@example.com"), "jane");
        when(accessTokenService.getOrganizationId("Bearer token")).thenReturn(Mono.just("VATES-A1"));

        // Act & Assert
        StepVerifier.create(resolve(user))
                .assertNext(context -> {
                    assertEquals(ActorKind.PERSON, context.actor().kind());
                    assertEquals("jane", context.actor().id());
                    assertEquals("jane@example.com", context.actor().email());
                    assertEquals("VATES-A1", context.organization());
                })
                .verifyComplete();
    }

    @Test
    void resolve_tokenWithoutOrganization_stillResolvesTheCaller() {
        // Arrange
        Authentication user = authentication(Map.of("sub", "user-1"), "jane");
        when(accessTokenService.getOrganizationId("Bearer token")).thenReturn(Mono.error(new IllegalStateException("no org")));

        // Act & Assert
        StepVerifier.create(resolve(user))
                .assertNext(context -> assertEquals(null, context.organization()))
                .verifyComplete();
    }

    @Test
    void resolve_requestWithoutAuthenticatedCaller_hasNoContext() {
        // Arrange & Act & Assert
        StepVerifier.create(resolve(null)).verifyComplete();
    }

    @Test
    void resolve_requestWithoutTenant_hasNoContext() {
        // Arrange
        Authentication user = authentication(Map.of("sub", "user-1"), "jane");

        // Act & Assert
        StepVerifier.create(resolver.resolve(exchange, user)).verifyComplete();
    }
}
