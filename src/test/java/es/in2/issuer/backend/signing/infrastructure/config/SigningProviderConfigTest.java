package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemorySigningProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SigningProviderConfigTest {

    @Mock
    private InMemorySigningProvider inMemorySigningProvider;

    @Mock
    private RuntimeSigningConfig runtimeSigningConfig;

    @InjectMocks
    private SigningProviderConfig config;
/*
    @BeforeEach
    void setUp() {
        when(runtimeSigningConfig.getProvider()).thenReturn("in-memory");
    }

    @Test
    void signingProvider_returnsDelegatingSigningProviderWithInMemory() {
        SigningProvider provider = config.signingProvider(runtimeSigningConfig, inMemorySigningProvider);
        assertNotNull(provider);
        assertInstanceOf(es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider.class, provider);
    }

    @Test
    void signingProvider_delegatesToInMemoryProvider() {
        SigningProvider provider = config.signingProvider(runtimeSigningConfig, inMemorySigningProvider);
        Object map = org.springframework.test.util.ReflectionTestUtils.getField(provider, "providersByKey");
        assertNotNull(map);
        assertTrue(((java.util.Map<?,?>)map).containsKey("in-memory"));
        assertEquals(inMemorySigningProvider, ((java.util.Map<?,?>)map).get("in-memory"));
    }

    @Test
    void signingProvider_delegatesToNullProviderThrows() {
        when(runtimeSigningConfig.getProvider()).thenReturn("unknown");
        SigningProvider provider = config.signingProvider(runtimeSigningConfig, inMemorySigningProvider);
        es.in2.issuer.backend.signing.domain.model.dto.SigningRequest request = mock(es.in2.issuer.backend.signing.domain.model.dto.SigningRequest.class);
        reactor.test.StepVerifier.create(provider.sign(request))
            .expectErrorMatches(e -> e instanceof es.in2.issuer.backend.signing.domain.exception.SigningException && e.getMessage().contains("No SigningProvider registered for key"))
            .verify();
    }
*/
}
