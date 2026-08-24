package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.apiclient.domain.service.ApiClientAuthenticationService;
import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndTxCode;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.PkceVerifier;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplAuthCodeTest {

    private static final String TOKEN_ENDPOINT_URI = "https://issuer/token";

    @Mock
    private TransientStore<IssuanceIdAndTxCode> txCodeCacheStore;
    @Mock
    private TransientStore<IssuanceIdAndRefreshToken> refreshTokenCacheStore;
    @Mock
    private TransientStore<AuthorizationCodeData> authorizationCodeCacheStore;
    @Mock
    private JWTService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private IssuanceService issuanceService;
    @Mock
    private PkceVerifier pkceVerifier;
    @Mock
    private DpopValidationService dpopValidationService;
    @Mock
    private Oid4vciProfilePort profileProperties;
    @Mock
    private IssuanceMetrics issuanceMetrics;
    @Mock
    private TransientStore<String> issuerStateCacheStore;
    @Mock
    private ApiClientAuthenticationService apiClientAuthenticationService;

    private TokenServiceImpl tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenServiceImpl(
                txCodeCacheStore,
                refreshTokenCacheStore,
                authorizationCodeCacheStore,
                jwtService,
                refreshTokenService,

                issuanceService,
                pkceVerifier,
                dpopValidationService,
                profileProperties,
                issuanceMetrics,
                issuerStateCacheStore,
                apiClientAuthenticationService
        );
    }

    private TokenRequest authCodeRequest(String code, String redirectUri, String codeVerifier) {
        return TokenRequest.builder()
                .grantType("authorization_code")
                .code(code)
                .redirectUri(redirectUri)
                .codeVerifier(codeVerifier)
                .build();
    }

    @Test
    void exchangeToken_authCode_shouldReturnBearerTokenWithPkce() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .issuerState("issuer-state-1")
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
        when(issuerStateCacheStore.get("issuer-state-1")).thenReturn(Mono.just("issuance-id-1"));
        when(jwtService.issueJWT(anyString())).thenReturn("signed-jwt-token");

        TokenRequest request = authCodeRequest("auth-code-123", "https://wallet/callback", "verifier");

        StepVerifier.create(tokenService.exchangeToken(request, null, TOKEN_ENDPOINT_URI, "https://issuer"))
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
    void exchangeToken_authCode_shouldReturnDpopTokenWhenDpopRequired() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .issuerState("issuer-state-2")
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
        when(dpopValidationService.validate("dpop-proof", "POST", TOKEN_ENDPOINT_URI))
                .thenReturn("dpop-jkt-thumbprint");
        when(issuerStateCacheStore.get("issuer-state-2")).thenReturn(Mono.just("issuance-id-2"));
        when(jwtService.issueJWT(anyString())).thenReturn("signed-dpop-jwt");

        TokenRequest request = authCodeRequest("auth-code-456", "https://wallet/callback", "verifier");

        StepVerifier.create(tokenService.exchangeToken(request, "dpop-proof", TOKEN_ENDPOINT_URI, "https://issuer"))
                .assertNext(response -> {
                    assertEquals("signed-dpop-jwt", response.accessToken());
                    assertEquals("DPoP", response.tokenType());
                    assertTrue(response.expiresIn() > 0);
                })
                .verifyComplete();
    }

    @Test
    void exchangeToken_authCode_shouldFailOnInvalidCode() {
        when(authorizationCodeCacheStore.get("invalid-code"))
                .thenReturn(Mono.empty());

        TokenRequest request = authCodeRequest("invalid-code", "https://wallet/callback", "verifier");

        StepVerifier.create(tokenService.exchangeToken(request, null, TOKEN_ENDPOINT_URI, "https://issuer"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException ex
                        && "invalid_grant".equals(ex.getErrorCode())
                        && e.getMessage().contains("Invalid or expired authorization code"))
                .verify();
    }

    @Test
    void exchangeToken_authCode_shouldFailOnRedirectUriMismatch() {
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .build();

        when(authorizationCodeCacheStore.get("code-789")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("code-789")).thenReturn(Mono.empty());

        TokenRequest request = authCodeRequest("code-789", "https://evil.example.com/callback", null);

        StepVerifier.create(tokenService.exchangeToken(request, null, TOKEN_ENDPOINT_URI, "https://issuer"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException ex
                        && "invalid_grant".equals(ex.getErrorCode())
                        && e.getMessage().contains("redirect_uri mismatch"))
                .verify();
    }

    @Test
    void exchangeToken_authCode_shouldFailOnPkceVerificationFailure() {
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

        TokenRequest request = authCodeRequest("code-pkce-fail", "https://wallet/callback", "wrong-verifier");

        StepVerifier.create(tokenService.exchangeToken(request, null, TOKEN_ENDPOINT_URI, "https://issuer"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException oAuthTokenException
                        && "invalid_request".equals(oAuthTokenException.getErrorCode())
                        && e.getMessage().contains("PKCE verification failed"))
                .verify();
    }

    @Test
    void exchangeToken_authCode_shouldFailOnMissingDpopProofWhenRequired() {
        // Regression test: DpopValidationService raises plain IllegalArgumentException, which
        // used to leak through as our internal GlobalErrorMessage shape (type/title/detail)
        // instead of the RFC 6749 §5.2 {error, error_description} shape /oauth/token must
        // return. Caught by the OIDF conformance suite's
        // fapi2-security-profile-final-ensure-holder-of-key-required test.
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .issuerState("issuer-state-dpop-fail")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, false, List.of("S256"),
                true, List.of("ES256"),
                "none", false
        );

        when(authorizationCodeCacheStore.get("code-dpop-fail")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("code-dpop-fail")).thenReturn(Mono.empty());
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        when(dpopValidationService.validate(null, "POST", TOKEN_ENDPOINT_URI))
                .thenThrow(new IllegalArgumentException("Missing DPoP proof"));

        TokenRequest request = authCodeRequest("code-dpop-fail", "https://wallet/callback", null);

        StepVerifier.create(tokenService.exchangeToken(request, null, TOKEN_ENDPOINT_URI, "https://issuer"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException oAuthTokenException
                        && "invalid_request".equals(oAuthTokenException.getErrorCode())
                        && e.getMessage().equals("Missing DPoP proof"))
                .verify();

        verify(issuerStateCacheStore, never()).get(anyString());
    }

    @Test
    void exchangeToken_authCode_shouldFailOnMissingIssuerStateInsteadOfCrashing() {
        // Regression test: issuer_state is OPTIONAL at the PAR/authorize level (a
        // wallet-initiated authorization request never sends one), but this Issuer can only
        // resolve the issuanceId an access token is bound to through it. A code without one
        // used to reach Guava's Cache.getIfPresent with a null key, which throws NPE and
        // surfaced as a raw 500 instead of a proper OAuth2 error. Caught by the OIDF
        // conformance suite's fapi2-security-profile-final-happy-flow test.
        AuthorizationCodeData codeData = AuthorizationCodeData.builder()
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .issuerState(null)
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, false, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(authorizationCodeCacheStore.get("code-no-issuer-state")).thenReturn(Mono.just(codeData));
        when(authorizationCodeCacheStore.delete("code-no-issuer-state")).thenReturn(Mono.empty());
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        TokenRequest request = authCodeRequest("code-no-issuer-state", "https://wallet/callback", null);

        StepVerifier.create(tokenService.exchangeToken(request, null, TOKEN_ENDPOINT_URI, "https://issuer"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException ex
                        && "invalid_grant".equals(ex.getErrorCode())
                        && e.getMessage().contains("issuer_state"))
                .verify();

        verify(issuerStateCacheStore, never()).get(anyString());
    }
}
