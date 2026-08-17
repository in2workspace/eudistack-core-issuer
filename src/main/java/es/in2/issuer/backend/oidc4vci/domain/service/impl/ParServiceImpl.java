package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.ParService;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.shared.domain.service.ClientAttestationValidationService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.PAR_CACHE_EXPIRY_SECONDS;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.PAR_REQUEST_URI_PREFIX;

@Slf4j
@Service
@RequiredArgsConstructor
public class ParServiceImpl implements ParService {

    private final TransientStore<PushedAuthorizationRequest> parCacheStore;
    private final Oid4vciProfilePort profileProperties;
    private final DpopValidationService dpopValidationService;
    private final ClientAttestationValidationService clientAttestationValidationService;

    @Override
    public Mono<PushedAuthorizationResponse> pushAuthorizationRequest(
            PushedAuthorizationRequest request,
            String dpopHeader,
            String wiaHeader,
            String wiaPopHeader,
            String requestUri,
            String publicIssuerUrl
    ) {
        // Each step is wrapped in Mono.defer so it only runs once the previous one has
        // completed (and not at all if an earlier one failed) - a plain chain of method
        // calls would evaluate every argument eagerly, up front, regardless of order.
        return Mono.defer(() -> validateResponseType(request))
                .then(Mono.defer(() -> validatePkce(request)))
                .then(Mono.defer(() -> validateDpop(dpopHeader, requestUri)))
                .then(Mono.defer(() -> validateWia(wiaHeader, wiaPopHeader, publicIssuerUrl)))
                .then(Mono.defer(() -> storeAndBuildResponse(request)));
    }

    private Mono<Void> validateResponseType(PushedAuthorizationRequest request) {
        if (!"code".equals(request.responseType())) {
            return Mono.error(OAuthTokenException.invalidRequest("response_type must be 'code'"));
        }
        return Mono.empty();
    }

    private Mono<Void> validatePkce(PushedAuthorizationRequest request) {
        if (!profileProperties.authorizationCode().requirePkce()) {
            return Mono.empty();
        }
        if (request.codeChallenge() == null || request.codeChallenge().isBlank()) {
            return Mono.error(OAuthTokenException.invalidRequest("code_challenge is required"));
        }
        if (!"S256".equals(request.codeChallengeMethod())) {
            return Mono.error(OAuthTokenException.invalidRequest("code_challenge_method must be S256"));
        }
        return Mono.empty();
    }

    // Per RFC 9449 §10.1, DPoP binding at the PAR endpoint is OPTIONAL — a client may instead
    // defer proof-of-possession entirely to the /token request. Only validate the header when
    // present; requireDpop() still governs enforcement at the token endpoint.
    private Mono<Void> validateDpop(String dpopHeader, String requestUri) {
        if (dpopHeader == null || dpopHeader.isBlank()) {
            return Mono.empty();
        }
        return Mono.fromRunnable(() -> dpopValidationService.validate(dpopHeader, "POST", requestUri))
                .onErrorMap(IllegalArgumentException.class, e -> OAuthTokenException.invalidRequest(e.getMessage()))
                .then();
    }

    private Mono<Void> validateWia(String wiaHeader, String wiaPopHeader, String publicIssuerUrl) {
        if (!"attest_jwt_client_auth".equals(profileProperties.authorizationCode().clientAuthMethod())) {
            return Mono.empty();
        }
        return Mono.fromRunnable(() -> clientAttestationValidationService.validateHeaders(wiaHeader, wiaPopHeader, publicIssuerUrl))
                .onErrorMap(IllegalArgumentException.class, e -> OAuthTokenException.invalidClient())
                .then();
    }

    private Mono<PushedAuthorizationResponse> storeAndBuildResponse(PushedAuthorizationRequest request) {
        String generatedRequestUri = PAR_REQUEST_URI_PREFIX + UUID.randomUUID();
        log.debug("PAR processed, request_uri={}", generatedRequestUri);
        return parCacheStore.add(generatedRequestUri, request)
                .map(saved -> PushedAuthorizationResponse.builder()
                        .requestUri(generatedRequestUri)
                        .expiresIn(PAR_CACHE_EXPIRY_SECONDS)
                        .build());
    }
}
