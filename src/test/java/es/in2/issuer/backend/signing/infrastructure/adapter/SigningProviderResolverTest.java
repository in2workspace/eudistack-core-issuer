package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SigningProviderResolverTest {

    private static SigningProvider providerOf(SigningModality modality) {
        SigningProvider provider = mock(SigningProvider.class);
        when(provider.modality()).thenReturn(modality);
        return provider;
    }

    @Test
    void resolve_everyModalityRegistered_returnsItsProvider() {
        SigningProvider qtsp = providerOf(SigningModality.QTSP);
        SigningProvider ownKey = providerOf(SigningModality.OWN_KEY);

        SigningProviderResolver resolver = new SigningProviderResolver(List.of(qtsp, ownKey));

        assertThat(resolver.resolve(SigningModality.QTSP)).isSameAs(qtsp);
        assertThat(resolver.resolve(SigningModality.OWN_KEY)).isSameAs(ownKey);
    }

    @Test
    void construction_modalityWithoutProvider_fails() {
        List<SigningProvider> onlyQtsp = List.of(providerOf(SigningModality.QTSP));

        assertThatThrownBy(() -> new SigningProviderResolver(onlyQtsp))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("No signing provider registered for the modalities [OWN_KEY]");
    }

    @Test
    void construction_noProviderAtAll_failsNamingEveryModality() {
        List<SigningProvider> none = List.of();

        assertThatThrownBy(() -> new SigningProviderResolver(none))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("No signing provider registered for the modalities [QTSP, OWN_KEY]");
    }

    @Test
    void construction_twoProvidersForOneModality_fails() {
        List<SigningProvider> duplicated = List.of(providerOf(SigningModality.QTSP),
                providerOf(SigningModality.QTSP), providerOf(SigningModality.OWN_KEY));

        assertThatThrownBy(() -> new SigningProviderResolver(duplicated))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Duplicated signing provider registration for 'QTSP'");
    }
}
