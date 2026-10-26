package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.test.StepVerifier;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.NotFoundException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsSigningAdapterTest {

    private static final String KEY_REF = "alias/cgcom-test";
    private static final byte[] DIGEST = new byte[32];
    private static final byte[] SIGNATURE = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    private static final Duration WAIT_ALL_RETRIES = Duration.ofMinutes(3);

    private KmsAsyncClient client;
    private KmsSigningAdapter adapter;

    @BeforeEach
    void setUp() {
        client = mock(KmsAsyncClient.class);
        adapter = new KmsSigningAdapter(client, new KmsSigningProperties(
                true, "eu-west-1", null, Duration.ofSeconds(10), 3, Duration.ofSeconds(1), Duration.ofSeconds(5)));
    }

    @Test
    void sign_throttledTwiceThenOk_returnsSignatureAfterThreeCalls() {
        when(client.sign(any(SignRequest.class))).thenReturn(
                failed(throttling()), failed(throttling()), CompletableFuture.completedFuture(signResponse()));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectNextMatches(sig -> java.util.Arrays.equals(sig, SIGNATURE))
                .verifyComplete();

        verify(client, times(3)).sign(any(SignRequest.class));
    }

    @Test
    void sign_sendsDigestWithEcdsaSha256() {
        when(client.sign(any(SignRequest.class))).thenReturn(CompletableFuture.completedFuture(signResponse()));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<SignRequest> captor = ArgumentCaptor.forClass(SignRequest.class);
        verify(client).sign(captor.capture());
        assertThat(captor.getValue().keyId()).isEqualTo(KEY_REF);
        assertThat(captor.getValue().messageType()).isEqualTo(MessageType.DIGEST);
        assertThat(captor.getValue().signingAlgorithm()).isEqualTo(SigningAlgorithmSpec.ECDSA_SHA_256);
        assertThat(captor.getValue().message().asByteArray()).isEqualTo(DIGEST);
    }

    @Test
    void sign_transientFailureOnEveryAttempt_failsProviderUnavailableAfterFourCalls() {
        when(client.sign(any(SignRequest.class))).thenAnswer(inv -> failed(throttling()));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> assertReason(ex, SigningFailureReason.PROVIDER_UNAVAILABLE))
                .verify();

        verify(client, times(4)).sign(any(SignRequest.class));
    }

    @Test
    void sign_disabledKey_failsKeyUnusableWithoutRetry() {
        assertNotRetried(DisabledException.builder().message("disabled").build());
    }

    @Test
    void sign_invalidKeyState_failsKeyUnusableWithoutRetry() {
        assertNotRetried(KmsInvalidStateException.builder().message("pending deletion").build());
    }

    @Test
    void sign_accessDenied_failsKeyUnusableWithoutRetryKeepingErrorCode() {
        AwsServiceException denied = AwsServiceException.builder()
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("AccessDeniedException").build())
                .build();
        when(client.sign(any(SignRequest.class))).thenReturn(failed(denied));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> {
                    assertReason(ex, SigningFailureReason.KEY_UNUSABLE);
                    assertThat(ex).hasMessageContaining("AccessDeniedException");
                })
                .verify();

        verify(client, times(1)).sign(any(SignRequest.class));
    }

    @Test
    void sign_keyNotFound_failsKeyUnusableWithoutRetry() {
        assertNotRetried(NotFoundException.builder().message("missing").build());
    }

    @Test
    void sign_callNeverCompletes_timesOutAtTenSecondsAndRetriesUntilProviderUnavailable() {
        when(client.sign(any(SignRequest.class))).thenAnswer(inv -> new CompletableFuture<SignResponse>());

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(Duration.ofSeconds(9))
                .then(() -> verify(client, times(1)).sign(any(SignRequest.class)))
                .thenAwait(Duration.ofSeconds(1))
                // Past the 10 s timeout the policy backs off (>= 0.5 s with jitter), then calls again
                .thenAwait(Duration.ofSeconds(2))
                .then(() -> verify(client, times(2)).sign(any(SignRequest.class)))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> assertReason(ex, SigningFailureReason.PROVIDER_UNAVAILABLE))
                .verify();

        verify(client, times(4)).sign(any(SignRequest.class));
    }

    @Test
    void sign_firstCallTimesOutSecondOk_returnsSignature() {
        when(client.sign(any(SignRequest.class))).thenReturn(
                new CompletableFuture<SignResponse>(), CompletableFuture.completedFuture(signResponse()));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(Duration.ofMinutes(1))
                .expectNextCount(1)
                .verifyComplete();

        verify(client, times(2)).sign(any(SignRequest.class));
    }

    @Test
    void sign_emptySignature_failsInvalidResponseWithoutRetry() {
        SignResponse empty = SignResponse.builder()
                .signature(SdkBytes.fromByteArray(new byte[0]))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .build();
        when(client.sign(any(SignRequest.class))).thenReturn(CompletableFuture.completedFuture(empty));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> assertReason(ex, SigningFailureReason.INVALID_RESPONSE))
                .verify();

        verify(client, times(1)).sign(any(SignRequest.class));
    }

    @Test
    void sign_wrongAlgorithmInResponse_failsInvalidResponseWithoutRetry() {
        SignResponse wrong = SignResponse.builder()
                .signature(SdkBytes.fromByteArray(SIGNATURE))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_384)
                .build();
        when(client.sign(any(SignRequest.class))).thenReturn(CompletableFuture.completedFuture(wrong));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> assertReason(ex, SigningFailureReason.INVALID_RESPONSE))
                .verify();

        verify(client, times(1)).sign(any(SignRequest.class));
    }

    @Test
    void sign_unknownException_failsOtherWithoutRetry() {
        when(client.sign(any(SignRequest.class))).thenReturn(failed(new IllegalStateException("boom")));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> assertReason(ex, SigningFailureReason.OTHER))
                .verify();

        verify(client, times(1)).sign(any(SignRequest.class));
    }

    @Test
    void sign_failureMessageWithTheKeyArn_isNotKeptInTheCauseChain() {
        String arn = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd";
        when(client.sign(any(SignRequest.class))).thenReturn(failed(DisabledException.builder()
                .message(arn + " is disabled.")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("DisabledException").build())
                .build()));

        StepVerifier.create(adapter.sign(KEY_REF, DIGEST))
                .expectErrorSatisfies(ex -> {
                    assertReason(ex, SigningFailureReason.KEY_UNUSABLE);
                    for (Throwable t = ex; t != null; t = t.getCause()) {
                        assertThat(String.valueOf(t.getMessage())).doesNotContain("111122223333");
                    }
                    assertThat(ex.getCause()).hasMessage("DisabledException (error=DisabledException)");
                    assertThat(ex.getCause().getStackTrace()).isNotEmpty();
                })
                .verify();
    }

    @Test
    void sign_retriesExhausted_causeKeepsTheErrorCodeButNotTheMessage() {
        when(client.sign(any(SignRequest.class))).thenAnswer(inv -> failed(throttling()));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> {
                    assertReason(ex, SigningFailureReason.PROVIDER_UNAVAILABLE);
                    assertThat(ex.getCause()).isInstanceOf(KmsRetryPolicy.KmsFailureCause.class);
                    assertThat(ex.getCause().getCause()).isNull();
                })
                .verify();
    }

    private void assertNotRetried(Throwable failure) {
        when(client.sign(any(SignRequest.class))).thenReturn(failed(failure));

        StepVerifier.withVirtualTime(() -> adapter.sign(KEY_REF, DIGEST))
                .thenAwait(WAIT_ALL_RETRIES)
                .expectErrorSatisfies(ex -> assertReason(ex, SigningFailureReason.KEY_UNUSABLE))
                .verify();

        verify(client, times(1)).sign(any(SignRequest.class));
    }

    private static void assertReason(Throwable ex, SigningFailureReason expected) {
        assertThat(ex).isInstanceOf(KmsSigningException.class);
        assertThat(((KmsSigningException) ex).getReason()).isEqualTo(expected);
    }

    private static SignResponse signResponse() {
        return SignResponse.builder()
                .signature(SdkBytes.fromByteArray(SIGNATURE))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .build();
    }

    private static AwsServiceException throttling() {
        return AwsServiceException.builder()
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("ThrottlingException").build())
                .build();
    }

    // The SDK completes its futures exceptionally with a CompletionException wrapping the error.
    private static <T> CompletableFuture<T> failed(Throwable error) {
        return CompletableFuture.failedFuture(new CompletionException(error));
    }
}
