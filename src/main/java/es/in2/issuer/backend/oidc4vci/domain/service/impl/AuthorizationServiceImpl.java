package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.service.AuthorizationService;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateSecureAuthorizationCode;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationServiceImpl implements AuthorizationService {

    private final TransientStore<PushedAuthorizationRequest> parCacheStore;
    private final TransientStore<AuthorizationCodeData> authorizationCodeCacheStore;
    private final Oid4vciProfilePort profileProperties;

    @Override
    public Mono<URI> authorize(
            String requestUri,
            String clientId,
            String responseType,
            String scope,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String redirectUri,
            String issuerState,
            String publicIssuerBaseUrl
    ) {
        if (requestUri != null && !requestUri.isBlank()) {
            return redeemPushedRequest(publicIssuerBaseUrl, requestUri, clientId, state);
        }
        // RFC 9126 §5: this Issuer advertises require_pushed_authorization_requests=true
        // (AuthorizationServerMetadataServiceImpl) whenever the profile requires PAR, so an
        // authorization request that skips it must be rejected here - otherwise the metadata
        // claim is a lie and a client can bypass PAR entirely by hitting /authorize directly.
        if (profileProperties.authorizationCode().requirePar()) {
            return Mono.error(OAuthTokenException.invalidRequest("Pushed Authorization Request is required"));
        }
        return processDirectAuthorization(
                publicIssuerBaseUrl, clientId, responseType, scope, state,
                codeChallenge, codeChallengeMethod, redirectUri, issuerState
        );
    }

    private Mono<URI> redeemPushedRequest(String baseUrl, String requestUri, String clientId, String state) {
        return parCacheStore.get(requestUri)
                .switchIfEmpty(Mono.error(OAuthTokenException.invalidRequest("Invalid or expired request_uri")))
                .flatMap(parRequest -> {
                    // RFC 9126 §4: a request_uri is bound to the client that pushed it. The
                    // authorization request MUST carry the same client_id, otherwise any client
                    // holding (or guessing) another client's request_uri could redeem it and
                    // obtain an authorization code issued against the victim's pushed request.
                    // Rejected before the one-time-use consumption below so a foreign client
                    // cannot burn a request_uri that is not its own.
                    if (!clientIdMatchesPushedRequest(parRequest.clientId(), clientId)) {
                        return Mono.error(OAuthTokenException.invalidRequest(
                                "client_id does not match the client that pushed the request_uri"));
                    }
                    // Consume the PAR (one-time use)
                    return parCacheStore.delete(requestUri)
                            .then(generateAndStoreAuthorizationCode(
                                    parRequest.clientId(),
                                    parRequest.redirectUri(),
                                    parRequest.codeChallenge(),
                                    parRequest.codeChallengeMethod(),
                                    parRequest.issuerState(),
                                    parRequest.scope(),
                                    null // dpopJkt stored separately if needed
                            ))
                            .map(code -> buildRedirectUri(
                                    baseUrl,
                                    parRequest.redirectUri(),
                                    code,
                                    state != null ? state : parRequest.state()
                            ));
                });
    }

    // Blank is treated as absent on both sides: a client that pushed no client_id (e.g. one
    // authenticated solely through client attestation) can only redeem its request_uri without
    // a client_id, and a request_uri pushed with a client_id can only be redeemed by that exact
    // client_id. Mismatch in either direction is an error.
    private boolean clientIdMatchesPushedRequest(String pushedClientId, String requestClientId) {
        return Objects.equals(normalizeClientId(pushedClientId), normalizeClientId(requestClientId));
    }

    private String normalizeClientId(String clientId) {
        return clientId == null || clientId.isBlank() ? null : clientId;
    }

    private Mono<URI> processDirectAuthorization(
            String baseUrl, String clientId, String responseType, String scope, String state,
            String codeChallenge, String codeChallengeMethod, String redirectUri,
            String issuerState
    ) {
        return Mono.defer(() -> {
            if (!"code".equals(responseType)) {
                return Mono.error(OAuthTokenException.invalidRequest("response_type must be 'code'"));
            }

            if (profileProperties.authorizationCode().requirePkce()) {
                if (codeChallenge == null || codeChallenge.isBlank()) {
                    return Mono.error(OAuthTokenException.invalidRequest("code_challenge is required"));
                }
                if (!"S256".equals(codeChallengeMethod)) {
                    return Mono.error(OAuthTokenException.invalidRequest("code_challenge_method must be S256"));
                }
            }

            return generateAndStoreAuthorizationCode(
                    clientId, redirectUri, codeChallenge, codeChallengeMethod,
                    issuerState, scope, null
            ).map(code -> buildRedirectUri(baseUrl, redirectUri, code, state));
        });
    }

    private Mono<String> generateAndStoreAuthorizationCode(
            String clientId, String redirectUri,
            String codeChallenge, String codeChallengeMethod,
            String issuerState, String scope, String dpopJkt
    ) {
        // RFC 6749 §10.10 / RFC 6819 §5.1.4.2-2 require sufficient entropy in the
        // authorization code to resist guessing attacks.
        return generateSecureAuthorizationCode()
                .flatMap(code -> {
                    AuthorizationCodeData data = AuthorizationCodeData.builder()
                            .clientId(clientId)
                            .redirectUri(redirectUri)
                            .codeChallenge(codeChallenge)
                            .codeChallengeMethod(codeChallengeMethod)
                            .issuerState(issuerState)
                            .scope(scope)
                            .dpopJkt(dpopJkt)
                            .build();

                    return authorizationCodeCacheStore.add(code, data)
                            .doOnSuccess(saved -> log.debug("Authorization code stored: {}", saved));
                });
    }

    private URI buildRedirectUri(String baseUrl, String redirectUri, String code, String state) {
        StringBuilder sb = new StringBuilder(redirectUri);
        sb.append(redirectUri.contains("?") ? "&" : "?");
        sb.append("code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8));
        if (state != null) {
            sb.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        sb.append("&iss=").append(URLEncoder.encode(baseUrl, StandardCharsets.UTF_8));
        return URI.create(sb.toString());
    }
}
