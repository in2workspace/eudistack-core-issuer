package es.in2.issuer.backend.signing.infrastructure.qtsp.auth;

import es.in2.issuer.backend.signing.infrastructure.model.QtspProvider;
import es.in2.issuer.backend.signing.domain.spi.QtspAuthPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class QtspAuthResolver {

    private final Map<QtspProvider, QtspAuthPort> authPortsByProvider;

    public QtspAuthResolver(List<QtspAuthPort> authPorts) {

        this.authPortsByProvider = buildProviderMap(authPorts);

        log.info(
                "QTSP auth providers registered: {}",
                authPortsByProvider.keySet()
        );
    }

    public QtspAuthPort resolveFromValue(String value) {

        QtspProvider provider = QtspProvider.fromValue(value)
                .orElse(QtspProvider.OAUTH_2);

        return resolve(provider);
    }

    private Map<QtspProvider, QtspAuthPort> buildProviderMap(
            List<QtspAuthPort> authPorts
    ) {

        Map<QtspProvider, QtspAuthPort> providerMap =
                new EnumMap<>(QtspProvider.class);

        for (QtspAuthPort authPort : authPorts) {

            QtspProvider provider = authPort.supportedProvider();

                QtspAuthPort previous =
                        providerMap.putIfAbsent(provider, authPort);

                if (previous != null) {
                    throw duplicatedProviderException(
                            provider,
                            previous,
                            authPort
                    );
            }
        }

        return Map.copyOf(providerMap);
    }

    private IllegalStateException duplicatedProviderException(
            QtspProvider provider,
            QtspAuthPort previous,
            QtspAuthPort current
    ) {

        return new IllegalStateException(
                "Duplicated QTSP auth provider registration for '%s'. "
                        .formatted(provider)
                        + "Already registered by "
                        + previous.getClass().getSimpleName()
                        + ", attempted registration by "
                        + current.getClass().getSimpleName()
        );
    }

    private QtspAuthPort resolve(QtspProvider provider) {

        return Optional.ofNullable(authPortsByProvider.get(provider))
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Unsupported auth provider: " + provider
                        ));
    }
}