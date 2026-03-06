package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.PkceVerifier;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.NoSuchElementException;

import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplTest {

    private static final String TEST_PRE_AUTHORIZED_CODE = "test-pre-auth-code-123";
    private static final String TEST_TX_CODE = "1234";
    private static final String TEST_CREDENTIAL_PROCEDURE_ID = "credential-procedure-123";
    private static final String TEST_ISSUER_URL = "https://issuer.example.com";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_REFRESH_TOKEN = "refresh-token-123";
    private static final long TEST_REFRESH_TOKEN_EXPIRES_AT = 1672531200L;
    private static final String INVALID_GRANT_TYPE = "invalid_grant_type";
    private static final String INVALID_TX_CODE = "wrong-tx-code";
    private static final String TOKEN_ENDPOINT_URI = "https://issuer.example.com/oauth/token";

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
    private ProcedureService procedureService;
    @Mock
    private PkceVerifier pkceVerifier;
    @Mock
    private DpopValidationService dpopValidationService;
    @Mock
    private Oid4vciProfileProperties profileProperties;
    @Mock
    private IssuanceMetrics issuanceMetrics;

    private TokenServiceImpl tokenService;
    private CredentialProcedureIdAndTxCode testCredentialProcedureIdAndTxCode;

    @BeforeEach
    void setUp() {
        tokenService = new TokenServiceImpl(
                txCodeCacheStore,
                refreshTokenCacheStore,
                authorizationCodeCacheStore,
                jwtService,
                refreshTokenService,
                appConfig,
                procedureService,
                pkceVerifier,
                dpopValidationService,
                profileProperties,
                issuanceMetrics
        );

        testCredentialProcedureIdAndTxCode = new CredentialProcedureIdAndTxCode(
                TEST_CREDENTIAL_PROCEDURE_ID,
                TEST_TX_CODE
        );
    }

    private TokenRequest preAuthRequest(String grantType, String preAuthCode, String txCode) {
        return TokenRequest.builder()
                .grantType(grantType)
                .preAuthorizedCode(preAuthCode)
                .txCode(txCode)
                .build();
    }

    @Test
    void handleToken_WhenValidPreAuthInputs_ShouldReturnTokenResponse() {
        when(txCodeCacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));
        when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);
        when(jwtService.generateJWT(anyString())).thenReturn(TEST_ACCESS_TOKEN);
        when(refreshTokenService.generateRefreshTokenExpirationTime(any(Instant.class)))
                .thenReturn(TEST_REFRESH_TOKEN_EXPIRES_AT);
        when(refreshTokenService.generateRefreshToken()).thenReturn(TEST_REFRESH_TOKEN);
        when(refreshTokenCacheStore.add(anyString(), any()))
                .thenReturn(Mono.just(TEST_REFRESH_TOKEN));

        TokenRequest request = preAuthRequest(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .assertNext(tokenResponse -> {
                    assertThat(tokenResponse).isNotNull();
                    assertThat(tokenResponse.accessToken()).isEqualTo(TEST_ACCESS_TOKEN);
                    assertThat(tokenResponse.tokenType()).isEqualTo("bearer");
                    assertThat(tokenResponse.expiresIn()).isGreaterThan(0);
                    assertThat(tokenResponse.refreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
                })
                .verifyComplete();

        verify(txCodeCacheStore, times(2)).get(TEST_PRE_AUTHORIZED_CODE);
        verify(jwtService).generateJWT(anyString());
        verify(refreshTokenService).generateRefreshToken();
        verify(refreshTokenCacheStore).add(eq(TEST_REFRESH_TOKEN), any(CredentialProcedureIdAndRefreshToken.class));
    }

    @Test
    void handleToken_WhenUnsupportedGrantType_ShouldReturnOAuthError() {
        TokenRequest request = preAuthRequest(INVALID_GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .expectErrorMatches(throwable ->
                        throwable instanceof OAuthTokenException ex &&
                                "unsupported_grant_type".equals(ex.getErrorCode()) &&
                                ex.getMessage().contains(INVALID_GRANT_TYPE))
                .verify();
    }

    @Test
    void handleToken_WhenInvalidPreAuthorizedCode_ShouldReturnInvalidGrant() {
        when(txCodeCacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.error(new NoSuchElementException("Not found")));

        TokenRequest request = preAuthRequest(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .expectErrorMatches(throwable ->
                        throwable instanceof OAuthTokenException ex &&
                                "invalid_grant".equals(ex.getErrorCode()) &&
                                ex.getMessage().equals("Invalid pre-authorized code"))
                .verify();

        verify(txCodeCacheStore).get(TEST_PRE_AUTHORIZED_CODE);
    }

    @Test
    void handleToken_WhenInvalidTxCode_ShouldReturnInvalidGrant() {
        when(txCodeCacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));

        TokenRequest request = preAuthRequest(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, INVALID_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .expectErrorMatches(throwable ->
                        throwable instanceof OAuthTokenException ex &&
                                "invalid_grant".equals(ex.getErrorCode()) &&
                                ex.getMessage().equals("Invalid tx code"))
                .verify();

        verify(txCodeCacheStore).get(TEST_PRE_AUTHORIZED_CODE);
    }

    @Test
    void handleToken_WhenCacheStoreThrowsException_ShouldReturnInvalidGrant() {
        when(txCodeCacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.error(new NoSuchElementException()));

        TokenRequest request = preAuthRequest(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .expectErrorMatches(throwable ->
                        throwable instanceof OAuthTokenException ex &&
                                "invalid_grant".equals(ex.getErrorCode()))
                .verify();

        verify(txCodeCacheStore).get(TEST_PRE_AUTHORIZED_CODE);
    }

    @Test
    void handleToken_WhenRefreshTokenCacheFails_ShouldReturnError() {
        when(txCodeCacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));
        when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);
        when(jwtService.generateJWT(anyString())).thenReturn(TEST_ACCESS_TOKEN);
        when(refreshTokenService.generateRefreshTokenExpirationTime(any(Instant.class)))
                .thenReturn(TEST_REFRESH_TOKEN_EXPIRES_AT);
        when(refreshTokenService.generateRefreshToken()).thenReturn(TEST_REFRESH_TOKEN);
        when(refreshTokenCacheStore.add(eq(TEST_REFRESH_TOKEN), any(CredentialProcedureIdAndRefreshToken.class)))
                .thenReturn(Mono.error(new RuntimeException("Refresh token cache error")));

        TokenRequest request = preAuthRequest(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .expectError(RuntimeException.class)
                .verify();

        verify(refreshTokenCacheStore).add(eq(TEST_REFRESH_TOKEN), any(CredentialProcedureIdAndRefreshToken.class));
    }

    @Test
    void handleToken_WhenJWTServiceFails_ShouldReturnError() {
        when(txCodeCacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));
        when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);
        when(jwtService.generateJWT(anyString())).thenThrow(new RuntimeException("JWT generation failed"));

        TokenRequest request = preAuthRequest(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE);

        StepVerifier.create(tokenService.handleToken(request, null, TOKEN_ENDPOINT_URI))
                .expectError(RuntimeException.class)
                .verify();

        verify(jwtService).generateJWT(anyString());
    }
}
