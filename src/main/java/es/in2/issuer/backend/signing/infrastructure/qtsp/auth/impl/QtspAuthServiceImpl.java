package es.in2.issuer.backend.signing.infrastructure.qtsp.auth.impl;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthResolver;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class QtspAuthServiceImpl implements QtspAuthService {

    private final QtspAuthResolver resolver;

    @Override
    public Mono<String> requestAccessToken(SigningRequest signingRequest, String scope, boolean includeAuthorizationDetails) {
        return resolver
                .resolveFromValue(signingRequest.remoteSignature().provider())
                .requestAccessToken(
                        signingRequest,
                        scope,
                        includeAuthorizationDetails
                );
    }
}
