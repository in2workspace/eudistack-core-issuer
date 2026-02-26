package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class DelegatingSigningProvider implements SigningProvider {

    private final RuntimeSigningConfig runtimeSigningConfig;
    private final Map<String, SigningProvider> providersByKey;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        String key = normalize(runtimeSigningConfig.getProvider());
        SigningProvider delegate = providersByKey.get(key);

        if (delegate == null) {
            return Mono.error(new SigningException(
                    "No SigningProvider registered for key '" + key + "'. " +
                            "Available: " + providersByKey.keySet()
            ));
        }

        log.info("Delegating signing to provider='{}' (available={})", key, providersByKey.keySet());
        return delegate.sign(request);
    }

    private static String normalize(String v) {
        return v == null ? "" : v.trim().toLowerCase();
    }
}