package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationManagerTest {

    @Mock private VerifierService verifierService;
    @Mock private JWTService jwtService;
    @Mock private AppConfig appConfig;
    @Mock private es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry credentialProfileRegistry;
    @Mock private AuditService auditService;

    private es.in2.issuer.backend.shared.infrastructure.config.security.CustomAuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        authenticationManager = new es.in2.issuer.backend.shared.infrastructure.config.security.CustomAuthenticationManager(
                verifierService,
                new ObjectMapper(),
                appConfig,
                jwtService,
                credentialProfileRegistry,
                auditService
        );
        lenient().doReturn("principal@example.com")
                .when(jwtService)
                .resolvePrincipal(any());
    }

    private String base64UrlEncode(String str) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    private String buildToken(String headerJson, String payloadJson) {
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String signature = base64UrlEncode("fake-signature");
        return header + "." + payload + "." + signature;
    }

    private String buildAccessTokenFromIssuer(String issuer, boolean includeCredentialType) {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        long now = Instant.now().getEpochSecond();
        String ctPart = includeCredentialType ? ",\"credential_type\":\"learcredential.machine.w3c.1\"" : "";
        String payloadJson = "{\"iss\":\"" + issuer + "\",\"iat\":" + now + ",\"exp\":" + (now + 3600) + ctPart + "}";
        return buildToken(headerJson, payloadJson);
    }

    private String buildIdTokenSimple(String subjectEmail) {
        String headerJson = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        long now = Instant.now().getEpochSecond();
        // No credential_type claim required for id token parsing path in resolvePrincipal...
        String payloadJson = "{\"sub\":\"" + subjectEmail + "\",\"iat\":" + now + ",\"exp\":" + (now + 3600) + "}";
        return buildToken(headerJson, payloadJson);
    }

    @Test
    void authenticate_withValidVerifierToken_returnsAuthentication() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800," +
                "\"exp\":" + (Instant.now().getEpochSecond() + 3600) + "," +
                "\"credential_type\":\"learcredential.machine.w3c.1\"}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.isVerifierIssuer("http://verifier.local")).thenReturn(true);
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();

        verify(jwtService, atLeastOnce()).resolvePrincipal(any(Jwt.class));
    }

    @Test
    void authenticate_withInvalidTokenFormat_throwsBadCredentialsException() {
        String token = "invalidToken";
        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Invalid JWT token format".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withVerifierToken_missingCredentialType_returnsAuthentication() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":1633040400}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.isVerifierIssuer("http://verifier.local")).thenReturn(true);
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();
    }

    @Test
    void authenticate_withVerifierToken_unknownCredentialType_returnsAuthentication() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":1633040400," +
                "\"credential_type\":\"SomeOtherType\"}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.isVerifierIssuer("http://verifier.local")).thenReturn(true);
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();
    }

    @Test
    void authenticate_withInvalidPayloadDecoding_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String header = base64UrlEncode(headerJson);
        String payload = "invalidPayload"; // not base64url-JSON
        String token = header + "." + payload + ".signature";

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Unable to parse JWT claims".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withVerifierServiceFailure_wrapsInAuthenticationServiceException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"exp\":1633040400," +
                "\"credential_type\":\"learcredential.machine.w3c.1\"}";
        String token = buildToken(headerJson, payloadJson);

        RuntimeException verifyException = new RuntimeException("Verification failed");

        when(appConfig.isVerifierIssuer("http://verifier.local")).thenReturn(true);
        when(verifierService.verifyToken(token)).thenReturn(Mono.error(verifyException));

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorSatisfies(e -> {
                    assert e instanceof AuthenticationServiceException;
                    AuthenticationServiceException ase = (AuthenticationServiceException) e;
                    assertEquals("Verification failed", ase.getMessage());
                    assertSame(verifyException, ase.getCause());
                })
                .verify();
    }

    @Test
    void authenticate_withValidInternalIssuerToken_returnsAuthentication() {
        String token = buildAccessTokenFromIssuer("http://issuer.local", true);

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(true));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();

        verify(jwtService, atLeastOnce()).resolvePrincipal(any(Jwt.class));
    }

    @Test
    void authenticate_withInternalIssuerToken_missingCredentialType_returnsAuthentication() {
        String token = buildAccessTokenFromIssuer("http://issuer.local", false);

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(true));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();
    }

    @Test
    void authenticate_withInternalIssuerToken_unknownCredentialType_returnsAuthentication() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        long now = Instant.now().getEpochSecond();
        String payloadJson = "{\"iss\":\"http://issuer.local\",\"iat\":" + now + ",\"exp\":" +
                (now + 3600) + ",\"credential_type\":\"OtherType\"}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(true));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("principal@example.com", auth.getName());
                })
                .verifyComplete();
    }

    @Test
    void authenticate_withInternalIssuerToken_invalidSignature_throwsBadCredentialsException() {
        String token = buildAccessTokenFromIssuer("http://issuer.local", false);

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(false));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Invalid JWT signature".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withDualToken_andValidIdToken_prefersIdTokenPrincipal() {
        String accessToken = buildAccessTokenFromIssuer("http://issuer.local", false);
        String idToken = buildIdTokenSimple("id-principal@example.com");

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));

        // Return different principals depending on which Jwt we parse
        when(jwtService.resolvePrincipal(any(Jwt.class))).thenAnswer(inv -> {
            Jwt jwt = inv.getArgument(0);
            if (jwt.getTokenValue().equals(idToken)) return "id-principal@example.com";
            if (jwt.getTokenValue().equals(accessToken)) return "access-principal@example.com";
            return "principal@example.com";
        });

        Authentication authentication = new es.in2.issuer.backend.shared.infrastructure.config.security.DualTokenAuthentication(accessToken, idToken);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> assertEquals("id-principal@example.com", auth.getName()))
                .verifyComplete();
    }

    @Test
    void authenticate_withDualToken_validIdTokenButNoPrincipal_fallsBackToAccessTokenPrincipal() {
        String accessToken = buildAccessTokenFromIssuer("http://issuer.local", false);
        String idToken = buildIdTokenSimple("ignored@example.com");

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));

        when(jwtService.resolvePrincipal(any(Jwt.class))).thenAnswer(inv -> {
            Jwt jwt = inv.getArgument(0);
            if (jwt.getTokenValue().equals(idToken)) return "  "; // blank forces fallback
            if (jwt.getTokenValue().equals(accessToken)) return "access-fallback@example.com";
            return "principal@example.com";
        });

        Authentication authentication = new es.in2.issuer.backend.shared.infrastructure.config.security.DualTokenAuthentication(accessToken, idToken);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> assertEquals("access-fallback@example.com", auth.getName()))
                .verifyComplete();
    }

    @Test
    void authenticate_withDualToken_invalidIdToken_fallsBackToAccessTokenPrincipal() {
        String accessToken = buildAccessTokenFromIssuer("http://issuer.local", false);
        String invalidIdToken = "not-a-jwt"; // triggers onErrorResume → fallback

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));

        when(jwtService.resolvePrincipal(any(Jwt.class))).thenAnswer(inv -> {
            Jwt jwt = inv.getArgument(0);
            if (jwt.getTokenValue().equals(accessToken)) return "from-access@example.com";
            return "principal@example.com";
        });

        Authentication authentication = new es.in2.issuer.backend.shared.infrastructure.config.security.DualTokenAuthentication(accessToken, invalidIdToken);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> assertEquals("from-access@example.com", auth.getName()))
                .verifyComplete();
    }

    @Test
    void authenticate_withDualToken_nullIdToken_usesAccessTokenPrincipal() {
        String accessToken = buildAccessTokenFromIssuer("http://issuer.local", true);

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));
        when(jwtService.resolvePrincipal(any(Jwt.class))).thenReturn("principal-from-access@example.com");

        Authentication authentication = new es.in2.issuer.backend.shared.infrastructure.config.security.DualTokenAuthentication(accessToken, null);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .assertNext(auth -> assertEquals("principal-from-access@example.com", auth.getName()))
                .verifyComplete();
    }


    @Test
    void authenticate_withUnknownIssuer_throwsBadCredentialsException() {
        String token = buildAccessTokenFromIssuer("http://unknown-issuer.local", false);

        when(appConfig.isIssuerBackendIssuer("http://unknown-issuer.local")).thenReturn(false);

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("Unknown token issuer: http://unknown-issuer.local"))
                .verify();
    }

    @Test
    void authenticate_withMissingIssuerClaim_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        long now = Instant.now().getEpochSecond();
        // No "iss" claim here
        String payloadJson = "{\"iat\":" + now + ",\"exp\":" + (now + 3600) + "}";
        String token = buildToken(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Missing issuer (iss) claim".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withIssuerBackendToken_invalidJwsFormat_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        long now = Instant.now().getEpochSecond();
        String payloadJson = "{\"iss\":\"http://issuer.local\",\"iat\":" + now + ",\"exp\":" + (now + 3600) + "}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        // invalid base64url signature (contains '=' in middle and non-url chars to provoke ParseException)
        String badSignature = "bad==signature/with+invalid";
        String token = header + "." + payload + "." + badSignature;

        when(appConfig.isIssuerBackendIssuer("http://issuer.local")).thenReturn(true);
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.error(new BadCredentialsException("Invalid JWS token format")));


        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Invalid JWS token format".equals(e.getMessage()))
                .verify();
    }

}
