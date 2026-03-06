package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.NONCE_CACHE_EXPIRY_SECONDS;

@Slf4j
@Service
@RequiredArgsConstructor
public class NonceServiceImpl implements NonceService {

    private final TransientStore<String> nonceCacheStore;

    @Override
    @Observed(name = "oid4vci.nonce", contextualName = "generate-nonce")
    public Mono<NonceResponse> issueNonce() {
        String nonce = UUID.randomUUID().toString();

        return nonceCacheStore.add(nonce, nonce)
                .map(saved -> NonceResponse.builder()
                        .cNonce(saved)
                        .cNonceExpiresIn(NONCE_CACHE_EXPIRY_SECONDS)
                        .build())
                .doOnSuccess(r -> log.debug("Generated nonce: {}", r.cNonce()));
    }
}
