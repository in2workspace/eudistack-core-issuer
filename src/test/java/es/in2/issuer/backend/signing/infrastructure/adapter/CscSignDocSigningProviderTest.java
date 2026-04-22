package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;

import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CscSignDocSigningProviderTest {
    @Mock
    private RemoteSignatureService remoteSignatureService;

    @InjectMocks
    private CscSignDocSigningProvider cscSignDocSigningProvider;

    private static SigningRequest buildRequest(SigningType type, String data, SigningContext ctx) {
        return SigningRequest.builder().type(type).data(data).context(ctx).build();
    }

    @Test
    void signReturnsSigningResultOnSuccess() {
        SigningContext context = new SigningContext("token", "issuanceId", "email@example.com");
        SigningRequest request = buildRequest(SigningType.JADES, "data", context);
        SigningResult signedData = new SigningResult(SigningType.JADES, "signedData");
        when(remoteSignatureService.signIssuedCredential(any(SigningRequest.class), eq("token"), eq("issuanceId"), eq("email@example.com")))
                .thenReturn(Mono.just(signedData));
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.JADES);
                    assertThat(result.data()).isEqualTo("signedData");
                })
                .verifyComplete();
    }

    @Test
    void signThrowsSigningExceptionOnNullRequest() {
        StepVerifier.create(cscSignDocSigningProvider.sign(null))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullType() {
        SigningContext context = new SigningContext("token", "issuanceId", "email@example.com");
        SigningRequest request = buildRequest(null, "data", context);
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullContext() {
        SigningRequest request = buildRequest(SigningType.JADES, "data", null);
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signPropagatesRemoteSignatureServiceError() {
        SigningContext context = new SigningContext("token", "issuanceId", "email@example.com");
        SigningRequest request = buildRequest(SigningType.JADES, "data", context);

        when(remoteSignatureService.signIssuedCredential(any(SigningRequest.class), eq("token"), eq("issuanceId"),
                eq("email@example.com"))).thenReturn(Mono.error(new RuntimeException("remote error")));

        StepVerifier.create(cscSignDocSigningProvider.sign(request)).expectError(SigningException.class).verify();
    }

    private static Object[][] invalidRequests() {
        SigningContext validContext = new SigningContext("token", "issuanceId", "email@example.com");
        return new Object[][]{
                {null, "Null request"},
                {buildRequest(null, "data", validContext), "Null type"},
                {buildRequest(SigningType.JADES, null, validContext), "Null data"},
                {buildRequest(SigningType.JADES, "   ", validContext), "Blank data"},
                {buildRequest(SigningType.JADES, "data", null), "Null context"},
                {buildRequest(SigningType.JADES, "data", new SigningContext(null, "issuanceId", "email@example.com")), "Null token"},
                {buildRequest(SigningType.JADES, "data", new SigningContext("   ", "issuanceId", "email@example.com")), "Blank token"}
        };
    }

    @ParameterizedTest(name = "{index}: {1}")
    @MethodSource("invalidRequests")
    void signThrowsSigningExceptionOnInvalidRequest(SigningRequest request, String description) {
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

}
