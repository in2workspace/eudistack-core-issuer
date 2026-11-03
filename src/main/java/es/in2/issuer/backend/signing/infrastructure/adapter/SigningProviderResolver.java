package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Registry of the signing providers by modality. Every {@link SigningModality} must have exactly one
 * provider: a missing or duplicated one fails the construction, so the application context does not start.
 */
@Slf4j
@Service
public class SigningProviderResolver {

    private final Map<SigningModality, SigningProvider> providersByModality;

    public SigningProviderResolver(List<SigningProvider> signingProviders) {

        this.providersByModality =
                buildProviderMap(signingProviders);

        log.info(
                "Signing providers registered: {}",
                providersByModality.keySet()
        );
    }

    public SigningProvider resolve(SigningModality modality) {

        return providersByModality.get(modality);
    }

    private Map<SigningModality, SigningProvider> buildProviderMap(
            List<SigningProvider> signingProviders
    ) {

        Map<SigningModality, SigningProvider> providerMap =
                new EnumMap<>(SigningModality.class);

        for (SigningProvider signingProvider : signingProviders) {

            SigningModality modality = signingProvider.modality();

            SigningProvider previous =
                    providerMap.putIfAbsent(
                            modality,
                            signingProvider
                    );

            if (previous != null) {
                throw duplicatedProviderException(
                        modality,
                        previous,
                        signingProvider
                );
            }
        }

        List<SigningModality> missing = Arrays.stream(SigningModality.values())
                .filter(modality -> !providerMap.containsKey(modality))
                .toList();

        if (!missing.isEmpty()) {
            throw new IllegalStateException(
                    "No signing provider registered for the modalities " + missing
            );
        }

        return Map.copyOf(providerMap);
    }

    private IllegalStateException duplicatedProviderException(
            SigningModality modality,
            SigningProvider previous,
            SigningProvider current
    ) {

        return new IllegalStateException(
                "Duplicated signing provider registration for '%s'. "
                        .formatted(modality)
                        + "Already registered by "
                        + previous.getClass().getSimpleName()
                        + ", attempted registration by "
                        + current.getClass().getSimpleName()
        );
    }
}
