package es.in2.issuer.backend.signing.infrastructure.csc.auth.impl;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAccessTokenService;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthStrategyResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class CscAccessTokenServiceImpl implements CscAccessTokenService {

    private final CscAuthStrategyResolver resolver;

    @Override
    public Mono<String> requestAccessToken(SigningRequest signingRequest, String scope, boolean includeAuthorizationDetails) {
        return resolver
                .resolveFromValue(signingRequest.remoteSignature().provider())
                .requestAccessToken(signingRequest, scope, includeAuthorizationDetails);
    }
}
