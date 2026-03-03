package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.PkceVerifier;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplAuthCodeTest {

    @Mock
    private CacheStore<CredentialProcedureIdAndTxCode> txCodeCacheStore;

    @Mock
    private CacheStore<CredentialProcedureIdAndRefreshToken> refreshTokenCacheStore;

    @Mock
    private CacheStore<AuthorizationCodeData> authorizationCodeCacheStore;

    @Mock
    private JWTService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private PkceVerifier pkceVerifier;

    @Mock
    private DpopValidationService dpopValidationService;

    @Mock
    private Oid4vciProfileProperties profileProperties;

    private TokenServiceImpl tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenServiceImpl(
                txCodeCacheStore,
                refreshTokenCacheStore,
                authorizationCodeCacheStore,
                jwtService,
                refreshTokenService,
                appConfig,
                credentialProcedureService,
                pkceVerifier,
                dpopValidationService,
                profileProperties
        );
    }

    @Test
    void generateTokenForAuthCode_shouldReturnBearerTokenWithPkce() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(authorizationCodeCacheStore.get("auth-code-123")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("auth-code-123")).thenReturn(Mono.empty());
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        doNothing().when(pkceVerifier).verifyS256("verifier", "challenge");
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");
        when(jwtService.generateJWT(anyString())).thenReturn("signed-jwt-token");

        StepVerifier.create(tokenService.generateTokenResponseForAuthorizationCode(
                        "auth-code-123", "https://wallet/callback", "verifier", null, "https://issuer/token"))
                .assertNext(response -> {
                    assertEquals("signed-jwt-token", response.accessToken());
                    assertEquals("bearer", response.tokenType());
                    assertTrue(response.expiresIn() > 0);
                    assertNull(response.refreshToken());
                })
                .verifyComplete();

        verify(pkceVerifier).verifyS256("verifier", "challenge");
        verify(dpopValidationService, never()).validate(anyString(), anyString(), anyString());
    }

    @Test
    void generateTokenForAuthCode_shouldReturnDpopTokenWhenDpopRequired() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                true, List.of("ES256"),
                "attest_jwt_client_auth", true
        );

        when(authorizationCodeCacheStore.get("auth-code-456")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("auth-code-456")).thenReturn(Mono.empty());
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        doNothing().when(pkceVerifier).verifyS256("verifier", "challenge");
        when(dpopValidationService.validate("dpop-proof", "POST", "https://issuer/token"))
                .thenReturn("dpop-jkt-thumbprint");
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");
        when(jwtService.generateJWT(anyString())).thenReturn("signed-dpop-jwt");

        StepVerifier.create(tokenService.generateTokenResponseForAuthorizationCode(
                        "auth-code-456", "https://wallet/callback", "verifier", "dpop-proof", "https://issuer/token"))
                .assertNext(response -> {
                    assertEquals("signed-dpop-jwt", response.accessToken());
                    assertEquals("DPoP", response.tokenType());
                    assertTrue(response.expiresIn() > 0);
                })
                .verifyComplete();
    }

    @Test
    void generateTokenForAuthCode_shouldFailOnInvalidCode() {
        when(authorizationCodeCacheStore.get("invalid-code"))
                .thenReturn(Mono.error(new NoSuchElementException("Not found")));

        StepVerifier.create(tokenService.generateTokenResponseForAuthorizationCode(
                        "invalid-code", "https://wallet/callback", "verifier", null, "https://issuer/token"))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("Invalid or expired authorization code"))
                .verify();
    }

    @Test
    void generateTokenForAuthCode_shouldFailOnRedirectUriMismatch() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .build();

        when(authorizationCodeCacheStore.get("code-789")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("code-789")).thenReturn(Mono.empty());

        StepVerifier.create(tokenService.generateTokenResponseForAuthorizationCode(
                        "code-789", "https://evil.example.com/callback", null, null, "https://issuer/token"))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("redirect_uri mismatch"))
                .verify();
    }

    @Test
    void generateTokenForAuthCode_shouldFailOnPkceVerificationFailure() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(authorizationCodeCacheStore.get("code-pkce-fail")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("code-pkce-fail")).thenReturn(Mono.empty());
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        doThrow(new IllegalArgumentException("PKCE verification failed"))
                .when(pkceVerifier).verifyS256("wrong-verifier", "challenge");

        StepVerifier.create(tokenService.generateTokenResponseForAuthorizationCode(
                        "code-pkce-fail", "https://wallet/callback", "wrong-verifier", null, "https://issuer/token"))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("PKCE verification failed"))
                .verify();
    }
}
