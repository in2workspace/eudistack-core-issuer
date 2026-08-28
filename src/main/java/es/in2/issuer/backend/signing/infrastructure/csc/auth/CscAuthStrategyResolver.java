package es.in2.issuer.backend.signing.infrastructure.csc.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class CscAuthStrategyResolver {

    private final Map<CscAuthProvider, CscAuthStrategy> strategiesByProvider;

    public CscAuthStrategyResolver(List<CscAuthStrategy> strategies) {
        this.strategiesByProvider = buildProviderMap(strategies);
        log.info("CSC auth strategies registered: {}", strategiesByProvider.keySet());
    }

    public CscAuthStrategy resolveFromValue(String value) {
        CscAuthProvider provider = CscAuthProvider.fromValue(value)
                .orElse(CscAuthProvider.OAUTH_2);
        return resolve(provider);
    }

    private Map<CscAuthProvider, CscAuthStrategy> buildProviderMap(List<CscAuthStrategy> strategies) {
        Map<CscAuthProvider, CscAuthStrategy> map = new EnumMap<>(CscAuthProvider.class);
        for (CscAuthStrategy strategy : strategies) {
            CscAuthProvider provider = strategy.supportedProvider();
            CscAuthStrategy previous = map.putIfAbsent(provider, strategy);
            if (previous != null) {
                throw new IllegalStateException(
                        "Duplicate CscAuthStrategy registration for '%s'. Already registered by %s, attempted by %s"
                                .formatted(provider, previous.getClass().getSimpleName(), strategy.getClass().getSimpleName()));
            }
        }
        return Map.copyOf(map);
    }

    private CscAuthStrategy resolve(CscAuthProvider provider) {
        return Optional.ofNullable(strategiesByProvider.get(provider))
                .orElseThrow(() -> new IllegalArgumentException("Unsupported CSC auth provider: " + provider));
    }
}
