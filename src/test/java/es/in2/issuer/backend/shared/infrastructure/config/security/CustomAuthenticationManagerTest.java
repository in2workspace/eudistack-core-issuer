package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationManagerTest {

    private static final String ISSUER_BASE_URL = "https://sandbox-stg.eudistack.net/issuer";
    private static final String VERIFIER_BASE_URL = "https://sandbox-stg.eudistack.net/verifier";

    @Mock private VerifierService verifierService;
    @Mock private JWTService jwtService;
    @Mock private CredentialProfileRegistry credentialProfileRegistry;
    @Mock private AuditService auditService;
    @Mock private UrlResolver urlResolver;

    private CustomAuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        authenticationManager = new CustomAuthenticationManager(
                verifierService,
                new ObjectMapper(),
                jwtService,
                credentialProfileRegistry,
                auditService,
                urlResolver
        );
        lenient().doReturn("principal@example.com").when(jwtService).resolvePrincipal(any());
        lenient().when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(ISSUER_BASE_URL);
        lenient().when(urlResolver.expectedVerifierBaseUrl(any())).thenReturn(VERIFIER_BASE_URL);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private static String base64UrlEncode(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String jwt(String iss) {
        long now = Instant.now().getEpochSecond();
        String header = base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        String payload = base64UrlEncode(
                "{\"iss\":\"" + iss + "\",\"iat\":" + now + ",\"exp\":" + (now + 3600) + "}");
        String sig = base64UrlEncode("fake-signature");
        return header + "." + payload + "." + sig;
    }

    private static ServerWebExchange exchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get(ISSUER_BASE_URL + "/api/v1/me"));
    }

    private Authentication authFor(String token, ServerWebExchange ex) {
        return new DualTokenAuthentication(token, null, ex);
    }

    // ── exact-match: issuer-backend token ───────────────────────────────

    @Test
    void authenticate_issuerToken_exactMatch_succeeds() {
        String token = jwt(ISSUER_BASE_URL);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));

        Mono<Authentication> result = authenticationManager.authenticate(authFor(token, exchange()));

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();
        verify(verifierService, never()).verifyToken(anyString());
    }

    @Test
    void authenticate_issuerToken_invalidSignature_fails() {
        String token = jwt(ISSUER_BASE_URL);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(false));

        Mono<Authentication> result = authenticationManager.authenticate(authFor(token, exchange()));

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException
                        && "Invalid JWT signature".equals(e.getMessage()))
                .verify();
    }

    // ── exact-match: verifier token ─────────────────────────────────────

    @Test
    void authenticate_verifierToken_exactMatch_delegatesToVerifierService() {
        String token = jwt(VERIFIER_BASE_URL);
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Mono<Authentication> result = authenticationManager.authenticate(authFor(token, exchange()));

        StepVerifier.create(result)
                .assertNext(auth -> assertTrue(auth instanceof JwtAuthenticationToken))
                .verifyComplete();
        verify(jwtService, never()).validateJwtSignatureReactive(any());
    }

    @Test
    void authenticate_verifierToken_verifierRejects_propagates() {
        String token = jwt(VERIFIER_BASE_URL);
        when(verifierService.verifyToken(token))
                .thenReturn(Mono.error(new RuntimeException("invalid signature")));

        Mono<Authentication> result = authenticationManager.authenticate(authFor(token, exchange()));

        StepVerifier.create(result)
                .expectErrorMatches(e -> e.getMessage() != null
                        && e.getMessage().contains("invalid signature"))
                .verify();
    }

    // ── rejections ──────────────────────────────────────────────────────

    @Test
    void authenticate_unknownIssuer_rejectedWithBadCredentials() {
        String token = jwt("https://attacker.example.com/issuer");

        Mono<Authentication> result = authenticationManager.authenticate(authFor(token, exchange()));

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException
                        && e.getMessage() != null
                        && e.getMessage().startsWith("Unknown token issuer"))
                .verify();
    }

    @Test
    void authenticate_withoutExchange_rejectedBecauseRequestContextUnavailable() {
        // A bare TestingAuthenticationToken (not DualTokenAuthentication) has no exchange.
        String token = jwt(ISSUER_BASE_URL);
        Authentication bare = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(bare);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e.getMessage() != null
                        && e.getMessage().contains("Request context unavailable"))
                .verify();
    }

    @Test
    void authenticate_invalidTokenFormat_rejectedWithBadCredentials() {
        Authentication bare = new TestingAuthenticationToken(null, "not-a-jwt");

        Mono<Authentication> result = authenticationManager.authenticate(bare);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException
                        && "Invalid JWT token format".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_missingIssuerClaim_rejectedWithBadCredentials() {
        long now = Instant.now().getEpochSecond();
        String header = base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        String payload = base64UrlEncode("{\"iat\":" + now + ",\"exp\":" + (now + 3600) + "}");
        String sig = base64UrlEncode("fake-signature");
        String token = header + "." + payload + "." + sig;

        Mono<Authentication> result = authenticationManager.authenticate(authFor(token, exchange()));

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException
                        && "Missing issuer (iss) claim".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_issuerToken_resolverNotConsultedForVerifierBranch() {
        // Sanity: when iss matches the issuer URL, the verifier branch is never
        // reached, so verifyToken/verifyTokenWithoutExpiration should not fire.
        String token = jwt(ISSUER_BASE_URL);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));

        authenticationManager.authenticate(authFor(token, exchange())).block();

        verify(verifierService, never()).verifyToken(anyString());
        verify(verifierService, never()).verifyTokenWithoutExpiration(anyString());
    }
}
