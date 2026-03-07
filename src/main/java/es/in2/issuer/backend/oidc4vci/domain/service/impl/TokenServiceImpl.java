package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.PkceVerifier;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.ACCESS_TOKEN_EXPIRATION_MINUTES;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.AUTHORIZATION_CODE_GRANT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.REFRESH_TOKEN_GRANT_TYPE;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private static final String TOKEN_TYPE_BEARER = "bearer";
    private static final String TOKEN_TYPE_DPOP = "DPoP";

    private final TransientStore<IssuanceIdAndTxCode> txCodeCacheStore;
    private final TransientStore<IssuanceIdAndRefreshToken> refreshTokenCacheStore;
    private final TransientStore<AuthorizationCodeData> authorizationCodeCacheStore;
    private final JWTService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final IssuerProperties appConfig;
    private final IssuanceService issuanceService;
    private final PkceVerifier pkceVerifier;
    private final DpopValidationService dpopValidationService;
    private final Oid4vciProfilePort profileProperties;
    private final IssuanceMetrics issuanceMetrics;
    private final TransientStore<String> issuerStateCacheStore;

    @Override
    @Observed(name = "oid4vci.token", contextualName = "oid4vci-handle-token")
    public Mono<TokenResponse> exchangeToken(TokenRequest request, String dpopHeader, String tokenEndpointUri) {
        String grantType = request.grantType();

        Mono<TokenResponse> flow;
        if (GRANT_TYPE.equals(grantType)) {
            flow = handlePreAuthorizedCode(request.preAuthorizedCode(), request.txCode());
        } else if (REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) {
            flow = handleRefreshToken(request.refreshToken());
        } else if (AUTHORIZATION_CODE_GRANT_TYPE.equals(grantType)) {
            flow = handleAuthorizationCode(request.code(), request.redirectUri(), request.codeVerifier(), dpopHeader, tokenEndpointUri);
        } else {
            return Mono.error(OAuthTokenException.unsupportedGrantType(grantType));
        }

        String grantTag = resolveGrantTag(grantType);
        return flow
                .doOnSuccess(r -> issuanceMetrics.recordTokenRequest(grantTag, "success"))
                .doOnError(e -> issuanceMetrics.recordTokenRequest(grantTag, "error"));
    }

    private String resolveGrantTag(String grantType) {
        if (GRANT_TYPE.equals(grantType)) return "pre-authorized_code";
        if (REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) return "refresh_token";
        if (AUTHORIZATION_CODE_GRANT_TYPE.equals(grantType)) return "authorization_code";
        return "unknown";
    }

    // ── Pre-Authorized Code Flow ──────────────────────────────────────────────

    private Mono<TokenResponse> handlePreAuthorizedCode(String preAuthorizedCode, String txCode) {
        log.debug("Token request: grant_type=pre-authorized_code");
        return validatePreAuthorizedCodeAndTxCode(preAuthorizedCode, txCode)
                .then(Mono.defer(() -> buildTokenResponse(preAuthorizedCode)));
    }

    private Mono<Void> validatePreAuthorizedCodeAndTxCode(String preAuthorizedCode, String txCode) {
        return txCodeCacheStore
                .get(preAuthorizedCode)
                .onErrorMap(NoSuchElementException.class, ex ->
                        OAuthTokenException.invalidGrant("Invalid pre-authorized code"))
                .flatMap(data -> {
                    if (data.TxCode().equals(txCode)) {
                        return Mono.empty();
                    }
                    log.warn("Invalid tx_code for pre-authorized code");
                    return Mono.error(OAuthTokenException.invalidGrant("Invalid tx code"));
                });
    }

    private Mono<TokenResponse> buildTokenResponse(String preAuthorizedCode) {
        Instant issueTime = Instant.now();
        long accessTokenExp = computeAccessTokenExpiration(issueTime);
        long refreshTokenExp = refreshTokenService.computeRefreshTokenExpirationTime(issueTime);
        String refreshToken = refreshTokenService.issueRefreshToken();

        return txCodeCacheStore.get(preAuthorizedCode)
                .map(IssuanceIdAndTxCode::issuanceId)
                .flatMap(issuanceId -> {
                    String accessToken = buildAccessToken(issuanceId, issueTime.getEpochSecond(), accessTokenExp);
                    return storeRefreshToken(issuanceId, preAuthorizedCode, refreshToken, refreshTokenExp)
                            .thenReturn(TokenResponse.builder()
                                    .accessToken(accessToken)
                                    .tokenType(TOKEN_TYPE_BEARER)
                                    .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                                    .refreshToken(refreshToken)
                                    .build());
                });
    }

    private String buildAccessToken(String issuanceId, long iat, long exp) {
        Payload payload = new Payload(Map.of(
                "iss", appConfig.getIssuerBackendUrl(),
                "aud", appConfig.getIssuerBackendUrl(),
                "iat", iat,
                "exp", exp,
                "jti", UUID.randomUUID().toString(),
                "pid", issuanceId
        ));
        return jwtService.issueJWT(payload.toString());
    }

    // ── Refresh Token Flow ────────────────────────────────────────────────────

    private Mono<TokenResponse> handleRefreshToken(String refreshToken) {
        log.debug("Token request: grant_type=refresh_token");
        return refreshTokenCacheStore
                .get(refreshToken)
                .onErrorMap(NoSuchElementException.class, ex ->
                        OAuthTokenException.invalidGrant("Invalid refresh token"))
                .flatMap(data -> validateRefreshTokenData(data, refreshToken)
                        .then(refreshTokenCacheStore.delete(refreshToken))
                        .then(Mono.defer(() -> buildRefreshedTokenResponse(data.issuanceId()))));
    }

    private Mono<Void> validateRefreshTokenData(IssuanceIdAndRefreshToken data, String refreshToken) {
        return issuanceService
                .getCredentialStatusByIssuanceId(data.issuanceId())
                .map(CredentialStatusEnum::valueOf)
                .flatMap(status -> {
                    if (CredentialStatusEnum.VALID.equals(status)) {
                        return Mono.error(OAuthTokenException.invalidGrant(
                                "Cannot refresh token: the associated credential is already valid"));
                    }
                    if (!data.refreshTokenJti().equals(refreshToken)) {
                        return Mono.error(OAuthTokenException.invalidGrant("Invalid refresh token"));
                    }
                    if (Instant.now().getEpochSecond() >= data.refreshTokenExpiresAt()) {
                        return Mono.error(OAuthTokenException.invalidGrant("Refresh token expired"));
                    }
                    return Mono.empty();
                });
    }

    private Mono<TokenResponse> buildRefreshedTokenResponse(String issuanceId) {
        Instant issueTime = Instant.now();
        long accessTokenExp = computeAccessTokenExpiration(issueTime);
        long refreshTokenExp = refreshTokenService.computeRefreshTokenExpirationTime(issueTime);
        String newRefreshToken = refreshTokenService.issueRefreshToken();
        String accessToken = buildAccessToken(issuanceId, issueTime.getEpochSecond(), accessTokenExp);

        return storeRefreshToken(issuanceId, null, newRefreshToken, refreshTokenExp)
                .thenReturn(TokenResponse.builder()
                        .accessToken(accessToken)
                        .tokenType(TOKEN_TYPE_BEARER)
                        .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                        .refreshToken(newRefreshToken)
                        .build());
    }

    // ── Authorization Code Flow ───────────────────────────────────────────────

    private Mono<TokenResponse> handleAuthorizationCode(
            String code, String redirectUri, String codeVerifier, String dpopHeader, String tokenEndpointUri
    ) {
        log.debug("Token request: grant_type=authorization_code");
        return authorizationCodeCacheStore.get(code)
                .onErrorMap(NoSuchElementException.class, ex ->
                        OAuthTokenException.invalidGrant("Invalid or expired authorization code"))
                .flatMap(codeData -> authorizationCodeCacheStore.delete(code)
                        .then(Mono.defer(() -> validateAndBuildAuthCodeToken(
                                codeData, redirectUri, codeVerifier, dpopHeader, tokenEndpointUri))));
    }

    private Mono<TokenResponse> validateAndBuildAuthCodeToken(
            AuthorizationCodeData codeData, String redirectUri,
            String codeVerifier, String dpopHeader, String tokenEndpointUri
    ) {
        if (codeData.redirectUri() != null && !codeData.redirectUri().equals(redirectUri)) {
            return Mono.error(OAuthTokenException.invalidGrant("redirect_uri mismatch"));
        }

        if (profileProperties.authorizationCode().requirePkce()) {
            pkceVerifier.verifyS256(codeVerifier, codeData.codeChallenge());
        }

        String dpopJkt = profileProperties.authorizationCode().requireDpop()
                ? dpopValidationService.validate(dpopHeader, "POST", tokenEndpointUri)
                : null;

        return issuerStateCacheStore.get(codeData.issuerState())
                .map(issuanceId -> buildAuthCodeTokenResponse(dpopJkt, issuanceId))
                .onErrorMap(NoSuchElementException.class, ex ->
                        OAuthTokenException.invalidGrant("Invalid or expired issuer_state"));
    }

    private TokenResponse buildAuthCodeTokenResponse(String dpopJkt, String issuanceId) {
        Instant issueTime = Instant.now();
        long accessTokenExp = computeAccessTokenExpiration(issueTime);
        boolean isDpop = dpopJkt != null;

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", appConfig.getIssuerBackendUrl());
        claims.put("aud", appConfig.getIssuerBackendUrl());
        claims.put("iat", issueTime.getEpochSecond());
        claims.put("exp", accessTokenExp);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("pid", issuanceId);
        if (isDpop) {
            claims.put("cnf", Map.of("jkt", dpopJkt));
        }

        String accessToken = jwtService.issueJWT(new Payload(claims).toString());

        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(isDpop ? TOKEN_TYPE_DPOP : TOKEN_TYPE_BEARER)
                .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                .refreshToken(null)
                .build();
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    private long computeAccessTokenExpiration(Instant issueTime) {
        return issueTime.plus(ACCESS_TOKEN_EXPIRATION_MINUTES, ChronoUnit.MINUTES).getEpochSecond();
    }

    private Mono<Void> storeRefreshToken(String issuanceId, String preAuthorizedCode, String refreshToken, long expiresAt) {
        IssuanceIdAndRefreshToken entry = IssuanceIdAndRefreshToken.builder()
                .preAuthorizedCode(preAuthorizedCode)
                .issuanceId(issuanceId)
                .refreshTokenJti(refreshToken)
                .refreshTokenExpiresAt(expiresAt)
                .build();
        return refreshTokenCacheStore.add(refreshToken, entry).then();
    }
}
