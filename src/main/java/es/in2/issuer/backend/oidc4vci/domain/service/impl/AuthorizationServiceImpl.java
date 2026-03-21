package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.service.AuthorizationService;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationServiceImpl implements AuthorizationService {

    private final TransientStore<PushedAuthorizationRequest> parCacheStore;
    private final TransientStore<AuthorizationCodeData> authorizationCodeCacheStore;
    private final Oid4vciProfilePort profileProperties;
    private final IssuerProperties appConfig;

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
            String issuerState
    ) {
        return Mono.deferContextual(ctx -> {
            String baseUrl = ctx.getOrDefault(ISSUER_BASE_URL_CONTEXT_KEY, appConfig.getIssuerBackendUrl());

            if (requestUri != null && !requestUri.isBlank()) {
                return pushAuthorizationRequestAuthorization(baseUrl, requestUri, state);
            } else {
                return processDirectAuthorization(
                        baseUrl, clientId, responseType, scope, state,
                        codeChallenge, codeChallengeMethod, redirectUri, issuerState
                );
            }
        });
    }

    private Mono<URI> pushAuthorizationRequestAuthorization(String baseUrl, String requestUri, String state) {
        return parCacheStore.get(requestUri)
                .flatMap(parRequest -> {
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
                })
                .onErrorMap(java.util.NoSuchElementException.class,
                        ex -> new IllegalArgumentException("Invalid or expired request_uri"));
    }

    private Mono<URI> processDirectAuthorization(
            String baseUrl, String clientId, String responseType, String scope, String state,
            String codeChallenge, String codeChallengeMethod, String redirectUri,
            String issuerState
    ) {
        return Mono.defer(() -> {
            if (!"code".equals(responseType)) {
                return Mono.error(new IllegalArgumentException("response_type must be 'code'"));
            }

            if (profileProperties.authorizationCode().requirePkce()) {
                if (codeChallenge == null || codeChallenge.isBlank()) {
                    return Mono.error(new IllegalArgumentException("code_challenge is required"));
                }
                if (!"S256".equals(codeChallengeMethod)) {
                    return Mono.error(new IllegalArgumentException("code_challenge_method must be S256"));
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
        return generateCustomNonce()
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
