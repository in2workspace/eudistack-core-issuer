package es.in2.issuer.backend.signing.infrastructure.adapter;

import org.mockito.*;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DelegatingSigningProviderTest {

    @Mock RuntimeSigningConfig runtimeSigningConfig;
    @Mock SigningProvider inMemoryProvider;
    @Mock SigningProvider cscSignHashProvider;

    private static SigningRequest anyValidRequest() {
        var ctx = new SigningContext("token", "procedureId", "email@example.com");
        return new SigningRequest(SigningType.JADES, "{\"vc\":\"unsigned\"}", ctx);
    }

    @Test
    void sign_delegatesToProvider_selectedByRuntimeConfig_normalized() {
        // given (nota: mixed case + spaces to test normalize)
        when(runtimeSigningConfig.getProvider()).thenReturn("  CSC-SIGN-HASH  ");

        SigningResult expected = new SigningResult(SigningType.JADES, "jwt");
        when(cscSignHashProvider.sign(any())).thenReturn(Mono.just(expected));

        DelegatingSigningProvider sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of(
                        "in-memory", inMemoryProvider,
                        "csc-sign-hash", cscSignHashProvider
                )
        );

        SigningRequest request = anyValidRequest();

        // when + then
        StepVerifier.create(sut.sign(request))
                .assertNext(actual -> {
                    assertEquals(expected.type(), actual.type());
                    assertEquals(expected.data(), actual.data());
                })
                .verifyComplete();

        verify(cscSignHashProvider).sign(request);
        verify(inMemoryProvider, never()).sign(any());
    }

    @Test
    void sign_returnsError_whenNoProviderRegistered() {
        // given
        when(runtimeSigningConfig.getProvider()).thenReturn("unknown-provider");

        DelegatingSigningProvider sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("in-memory", inMemoryProvider)
        );

        // when + then
        StepVerifier.create(sut.sign(anyValidRequest()))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertTrue(ex.getMessage().contains("No SigningProvider registered for key 'unknown-provider'"));
                    assertTrue(ex.getMessage().contains("Available:"));
                    assertTrue(ex.getMessage().contains("in-memory"));
                })
                .verify();

        verifyNoInteractions(inMemoryProvider);
    }

    @Test
    void sign_usesEmptyKey_whenRuntimeConfigReturnsNull() {
        // given
        when(runtimeSigningConfig.getProvider()).thenReturn(null);

        DelegatingSigningProvider sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("in-memory", inMemoryProvider)
        );

        StepVerifier.create(sut.sign(anyValidRequest()))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertTrue(ex.getMessage().contains("key ''"));
                })
                .verify();

        verifyNoInteractions(inMemoryProvider);
    }

    @Test
    void sign_propagatesDelegateError() {
        // given
        when(runtimeSigningConfig.getProvider()).thenReturn("in-memory");

        when(inMemoryProvider.sign(any()))
                .thenReturn(Mono.error(new SigningException("delegate failed")));

        DelegatingSigningProvider sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("in-memory", inMemoryProvider)
        );

        // when + then
        StepVerifier.create(sut.sign(anyValidRequest()))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertEquals("delegate failed", ex.getMessage());
                })
                .verify();

        verify(inMemoryProvider).sign(any());
    }
}