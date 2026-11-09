package es.in2.issuer.backend.shared.infrastructure.audit;

import com.eudistack.auditoria.domain.ActorKind;
import com.eudistack.auditoria.domain.AuditContext;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
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
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IssuerAuditContextResolverTest {

    private final AccessTokenService accessTokenService = mock(AccessTokenService.class);
    private final JWTService jwtService = mock(JWTService.class);
    private final IssuerAuditContextResolver resolver =
            new IssuerAuditContextResolver(accessTokenService, new AccessTokenActor(jwtService));
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
                    assertEquals("jane@example.com", context.actor().id());
                    assertEquals("jane@example.com", context.actor().email());
                    assertEquals("VATES-A1", context.organization());
                })
                .verifyComplete();
    }

    @Test
    void resolve_forgedPrincipal_isIgnoredAndTheActorIsTheMandateeOfTheAccessToken() {
        // Arrange: the principal comes from an X-ID-Token nobody verified and names somebody else
        Map<String, Object> claims = Map.of("sub", "user-1");
        Authentication forged = authentication(claims, "ceo@victim.example");
        when(jwtService.extractMandateeEmail(claims)).thenReturn(Optional.of("real@example.com"));
        when(accessTokenService.getOrganizationId("Bearer token")).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(resolve(forged))
                .assertNext(context -> {
                    assertEquals(ActorKind.PERSON, context.actor().kind());
                    assertEquals("real@example.com", context.actor().id());
                    assertEquals("real@example.com", context.actor().email());
                })
                .verifyComplete();
    }

    @Test
    void resolve_machineAttestationToken_isASystemNamedByTheDidOfItsMandatee() {
        // Arrange: no client_id; sub is the IP the attestation declares and must not name the system
        Map<String, Object> claims = Map.of(
                "sub", "127.0.0.1",
                "credential_type", "learcredential.machine.w3c.3",
                "mandatee", Map.of("id", "did:key:zMachine"));
        Authentication machine = authentication(claims, "someone-else");
        when(accessTokenService.getOrganizationId("Bearer token")).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(resolve(machine))
                .assertNext(context -> {
                    assertEquals(ActorKind.SYSTEM, context.actor().kind());
                    assertEquals("did:key:zMachine", context.actor().id());
                })
                .verifyComplete();
    }

    @Test
    void resolve_personWithNothingToIdentifyThem_isAnUnidentifiedPersonInsteadOfFailing() {
        // Arrange
        Authentication user = authentication(Map.of("iss", "verifier"), "anonymous");
        when(accessTokenService.getOrganizationId("Bearer token")).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(resolve(user))
                .assertNext(context -> assertEquals("unidentified", context.actor().id()))
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
