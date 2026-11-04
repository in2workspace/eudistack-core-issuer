package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CscQtspSigningProviderTest {

    private final CscSignHashSigningProvider signHash = mock(CscSignHashSigningProvider.class);
    private final CscSignDocSigningProvider signDoc = mock(CscSignDocSigningProvider.class);
    private final CscQtspSigningProvider provider = new CscQtspSigningProvider(signHash, signDoc);

    private static RemoteSignatureDto cfgWithOperation(String operation) {
        return new RemoteSignatureDto("provider", "2", "https://qtsp.test", "https://qtsp.test", operation,
                "cred-123", "pwd", "PT10M", "clientId", "clientSecret", "", "", "", "", "");
    }

    private static SigningRequest requestWith(RemoteSignatureDto config) {
        return SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{\"vc\":\"unsigned\"}")
                .remoteSignature(config)
                .build();
    }

    @Test
    void modality_isQtsp() {
        assertThat(provider.modality()).isEqualTo(SigningModality.QTSP);
    }

    @Test
    void sign_signHashOperation_delegatesToSignHashUnchanged() {
        SigningRequest request = requestWith(cfgWithOperation("sign-hash"));
        SigningResult expected = new SigningResult(SigningType.JADES, "jws-hash");
        when(signHash.sign(request)).thenReturn(Mono.just(expected));

        StepVerifier.create(provider.sign(request)).expectNext(expected).verifyComplete();

        verify(signHash).sign(request);
        verifyNoInteractions(signDoc);
    }

    @Test
    void sign_signDocOperation_delegatesToSignDocUnchanged() {
        SigningRequest request = requestWith(cfgWithOperation("sign-doc"));
        SigningResult expected = new SigningResult(SigningType.JADES, "jws-doc");
        when(signDoc.sign(request)).thenReturn(Mono.just(expected));

        StepVerifier.create(provider.sign(request)).expectNext(expected).verifyComplete();

        verify(signDoc).sign(request);
        verifyNoInteractions(signHash);
    }

    @Test
    void sign_delegateError_reachesTheCallerUnchanged() {
        SigningRequest request = requestWith(cfgWithOperation("sign-hash"));
        SigningException failure = new SigningException("delegate failed");
        when(signHash.sign(request)).thenReturn(Mono.error(failure));

        StepVerifier.create(provider.sign(request))
                .expectErrorSatisfies(error -> assertThat(error).isSameAs(failure))
                .verify();
    }

    @Test
    void sign_withoutOperation_failsWithoutSigning() {
        StepVerifier.create(provider.sign(requestWith(cfgWithOperation(null))))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(SigningException.class)
                        .hasMessageContaining("signingOperation is required"))
                .verify();

        verifyNoInteractions(signHash, signDoc);
    }

    @Test
    void sign_unknownOperation_failsWithoutSigning() {
        StepVerifier.create(provider.sign(requestWith(cfgWithOperation("aws-kms"))))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessage("Unsupported CSC signing type: aws-kms"))
                .verify();

        verifyNoInteractions(signHash, signDoc);
    }

    @Test
    void sign_withoutQtspConfiguration_failsWithoutSigning() {
        StepVerifier.create(provider.sign(requestWith(null)))
                .expectError(SigningException.class)
                .verify();

        verifyNoInteractions(signHash, signDoc);
    }
}
