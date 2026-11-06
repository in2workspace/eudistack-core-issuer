package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.model.DependencyTimeoutException;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.InvalidKeyUsageException;
import software.amazon.awssdk.services.kms.model.KeyUnavailableException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.NotFoundException;

import java.io.IOException;
import java.net.ConnectException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import static es.in2.issuer.backend.signing.domain.model.SigningFailureReason.KEY_UNUSABLE;
import static es.in2.issuer.backend.signing.domain.model.SigningFailureReason.OTHER;
import static es.in2.issuer.backend.signing.domain.model.SigningFailureReason.PROVIDER_UNAVAILABLE;
import static org.assertj.core.api.Assertions.assertThat;

class KmsRetryPolicyTest {

    static Stream<Arguments> classificationTable() {
        return Stream.of(
                Arguments.of("throttling by error code", serviceError(400, "ThrottlingException"), PROVIDER_UNAVAILABLE, true),
                Arguments.of("throttling by status 429", serviceError(429, "SomethingElse"), PROVIDER_UNAVAILABLE, true),
                Arguments.of("KmsInternalException", KmsInternalException.builder().message("x").build(), PROVIDER_UNAVAILABLE, true),
                Arguments.of("DependencyTimeoutException", DependencyTimeoutException.builder().message("x").build(), PROVIDER_UNAVAILABLE, true),
                Arguments.of("KeyUnavailableException", KeyUnavailableException.builder().message("x").build(), PROVIDER_UNAVAILABLE, true),
                Arguments.of("5xx service error", serviceError(503, "ServiceUnavailable"), PROVIDER_UNAVAILABLE, true),
                Arguments.of("ApiCallTimeoutException", ApiCallTimeoutException.create(1000), PROVIDER_UNAVAILABLE, true),
                Arguments.of("ApiCallAttemptTimeoutException", ApiCallAttemptTimeoutException.create(1000), PROVIDER_UNAVAILABLE, true),
                Arguments.of("Reactor TimeoutException", new TimeoutException("timeout"), PROVIDER_UNAVAILABLE, true),
                Arguments.of("IOException", new IOException("reset"), PROVIDER_UNAVAILABLE, true),
                Arguments.of("SdkClientException caused by IOException",
                        SdkClientException.builder().message("Unable to execute HTTP request").cause(new ConnectException("refused")).build(),
                        PROVIDER_UNAVAILABLE, true),
                Arguments.of("retryable cause behind CompletionException",
                        new CompletionException(new RuntimeException("wrapper", serviceError(400, "ThrottlingException"))),
                        PROVIDER_UNAVAILABLE, true),
                Arguments.of("DisabledException", DisabledException.builder().message("x").build(), KEY_UNUSABLE, false),
                Arguments.of("KmsInvalidStateException", KmsInvalidStateException.builder().message("x").build(), KEY_UNUSABLE, false),
                Arguments.of("NotFoundException", NotFoundException.builder().message("x").build(), KEY_UNUSABLE, false),
                Arguments.of("InvalidKeyUsageException", InvalidKeyUsageException.builder().message("x").build(), KEY_UNUSABLE, false),
                Arguments.of("AccessDeniedException", serviceError(400, "AccessDeniedException"), KEY_UNUSABLE, false),
                Arguments.of("AccessDenied behind CompletionException",
                        new CompletionException(serviceError(400, "AccessDeniedException")), KEY_UNUSABLE, false),
                Arguments.of("other 4xx service error", serviceError(400, "ValidationException"), OTHER, false),
                Arguments.of("SdkClientException without I/O cause",
                        SdkClientException.builder().message("Unable to load credentials").build(), OTHER, false),
                Arguments.of("unknown exception", new IllegalStateException("boom"), OTHER, false)
        );
    }

    @ParameterizedTest(name = "{0} -> {2}, retryable={3}")
    @MethodSource("classificationTable")
    void classifyAndIsRetryable_perCase_matchTable(String name, Throwable error, SigningFailureReason reason, boolean retryable) {
        assertThat(KmsRetryPolicy.classify(error)).isEqualTo(reason);
        assertThat(KmsRetryPolicy.isRetryable(error)).isEqualTo(retryable);
    }

    @Test
    void classifyAndIsRetryable_alreadyClassifiedSigningException_keepsReasonAndIsNotRetried() {
        KmsSigningException exhausted = new KmsSigningException(PROVIDER_UNAVAILABLE, "gave up", serviceError(400, "ThrottlingException"));
        KmsSigningException invalid = new KmsSigningException(SigningFailureReason.INVALID_RESPONSE, "empty");

        assertThat(KmsRetryPolicy.classify(exhausted)).isEqualTo(PROVIDER_UNAVAILABLE);
        assertThat(KmsRetryPolicy.isRetryable(exhausted)).isFalse();
        assertThat(KmsRetryPolicy.classify(invalid)).isEqualTo(SigningFailureReason.INVALID_RESPONSE);
        assertThat(KmsRetryPolicy.isRetryable(invalid)).isFalse();
    }

    @Test
    void toSigningException_accessDenied_keepsOriginalErrorCodeInMessage() {
        KmsSigningException ex = KmsRetryPolicy.toSigningException(serviceError(400, "AccessDeniedException"), "Sign");

        assertThat(ex.getReason()).isEqualTo(KEY_UNUSABLE);
        assertThat(ex).hasMessageContaining("AccessDeniedException");
    }

    @Test
    void toSigningException_unknownException_doesNotLeakOriginalMessage() {
        KmsSigningException ex = KmsRetryPolicy.toSigningException(new IllegalStateException("secret-detail"), "Sign");

        assertThat(ex.getReason()).isEqualTo(OTHER);
        assertThat(ex.getMessage()).doesNotContain("secret-detail").contains("IllegalStateException");
    }

    private static AwsServiceException serviceError(int status, String errorCode) {
        return AwsServiceException.builder()
                .statusCode(status)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode(errorCode).build())
                .build();
    }
}
