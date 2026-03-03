package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.ParService;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.service.ClientAttestationValidationService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
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

    private final CacheStore<PushedAuthorizationRequest> parCacheStore;
    private final Oid4vciProfileProperties profileProperties;
    private final DpopValidationService dpopValidationService;
    private final ClientAttestationValidationService clientAttestationValidationService;

    @Override
    public Mono<PushedAuthorizationResponse> processPar(
            PushedAuthorizationRequest request,
            String dpopHeader,
            String wiaHeader,
            String wiaPopHeader,
            String requestUri
    ) {
        return Mono.defer(() -> {
            // Validate response_type
            if (!"code".equals(request.responseType())) {
                return Mono.error(new IllegalArgumentException("response_type must be 'code'"));
            }

            // Validate code_challenge_method if PKCE required
            if (profileProperties.authorizationCode().requirePkce()) {
                if (request.codeChallenge() == null || request.codeChallenge().isBlank()) {
                    return Mono.error(new IllegalArgumentException("code_challenge is required"));
                }
                if (!"S256".equals(request.codeChallengeMethod())) {
                    return Mono.error(new IllegalArgumentException("code_challenge_method must be S256"));
                }
            }

            // Validate DPoP if required
            String dpopJkt = null;
            if (profileProperties.authorizationCode().requireDpop()) {
                dpopJkt = dpopValidationService.validate(dpopHeader, "POST", requestUri);
            }

            // Validate WIA if required
            if ("attest_jwt_client_auth".equals(profileProperties.authorizationCode().clientAuthMethod())) {
                clientAttestationValidationService.validateHeaders(wiaHeader, wiaPopHeader);
            }

            // Generate request_uri and store in cache
            String generatedRequestUri = PAR_REQUEST_URI_PREFIX + UUID.randomUUID();
            log.debug("PAR processed, request_uri={}", generatedRequestUri);

            // Store request with dpopJkt for later validation at token endpoint
            // We store the original request; dpopJkt is passed through via AuthorizationCodeData later
            return parCacheStore.add(generatedRequestUri, request)
                    .map(saved -> PushedAuthorizationResponse.builder()
                            .requestUri(generatedRequestUri)
                            .expiresIn(PAR_CACHE_EXPIRY_SECONDS)
                            .build());
        });
    }
}
