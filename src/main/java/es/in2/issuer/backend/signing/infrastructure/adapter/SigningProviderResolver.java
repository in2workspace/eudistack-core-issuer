package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class SigningProviderResolver {

    private final Map<SigningProviderType, SigningProvider> providersByType;

    public SigningProviderResolver(List<SigningProvider> signingProviders) {

        this.providersByType =
                buildProviderMap(signingProviders);

        log.info(
                "Signing providers registered: {}",
                providersByType.keySet()
        );
    }

    /** Provider of the CSC operation ({@code signingOperation}) of a QTSP configuration. */
    public SigningProvider resolveFromValue(String value) {

        SigningProviderType providerType = SigningProviderType.fromCscOperation(value);

        return resolve(providerType);
    }

    public SigningProvider resolve(SigningProviderType provider) {

        SigningProvider signingProvider =
                providersByType.get(provider);

        if (signingProvider == null) {
            throw new IllegalArgumentException(
                    "Unsupported signing provider: " + provider
            );
        }

        return signingProvider;
    }

    private Map<SigningProviderType, SigningProvider> buildProviderMap(
            List<SigningProvider> signingProviders
    ) {

        Map<SigningProviderType, SigningProvider> providerMap =
                new EnumMap<>(SigningProviderType.class);

        for (SigningProvider signingProvider : signingProviders) {

            SigningProviderType providerType = signingProvider.supportedProvider();

                SigningProvider previous =
                        providerMap.putIfAbsent(
                                providerType,
                                signingProvider
                        );

                if (previous != null) {
                    throw duplicatedProviderException(
                            providerType,
                            previous,
                            signingProvider
                    );
                }
        }

        return Map.copyOf(providerMap);
    }

    private IllegalStateException duplicatedProviderException(
            SigningProviderType provider,
            SigningProvider previous,
            SigningProvider current
    ) {

        return new IllegalStateException(
                "Duplicated signing provider registration for '%s'. "
                        .formatted(provider)
                        + "Already registered by "
                        + previous.getClass().getSimpleName()
                        + ", attempted registration by "
                        + current.getClass().getSimpleName()
        );
    }
}