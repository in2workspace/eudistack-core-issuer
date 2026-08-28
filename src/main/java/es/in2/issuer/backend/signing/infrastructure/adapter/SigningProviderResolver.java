package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.model.CscSignType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class SigningProviderResolver {

    private final Map<CscSignType, SigningProvider> providersByCscSignType;

    public SigningProviderResolver(List<SigningProvider> signingProviders) {

        this.providersByCscSignType =
                buildProviderMap(signingProviders);

        log.info(
                "Signing providers registered: {}",
                providersByCscSignType.keySet()
        );
    }

    public SigningProvider resolveFromValue(String value) {

        CscSignType cscSignType = CscSignType.fromValue(value);

        return resolve(cscSignType);
    }

    private SigningProvider resolve(CscSignType provider) {

        SigningProvider signingProvider =
                providersByCscSignType.get(provider);

        if (signingProvider == null) {
            throw new IllegalArgumentException(
                    "Unsupported signing provider: " + provider
            );
        }

        return signingProvider;
    }

    private Map<CscSignType, SigningProvider> buildProviderMap(
            List<SigningProvider> signingProviders
    ) {

        Map<CscSignType, SigningProvider> providerMap =
                new EnumMap<>(CscSignType.class);

        for (SigningProvider signingProvider : signingProviders) {

            CscSignType cscSignType = signingProvider.supportedProvider();

                SigningProvider previous =
                        providerMap.putIfAbsent(
                                cscSignType,
                                signingProvider
                        );

                if (previous != null) {
                    throw duplicatedProviderException(
                            cscSignType,
                            previous,
                            signingProvider
                    );
                }
        }

        return Map.copyOf(providerMap);
    }

    private IllegalStateException duplicatedProviderException(
            CscSignType provider,
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