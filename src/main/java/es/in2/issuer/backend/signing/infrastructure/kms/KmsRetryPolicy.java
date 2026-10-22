package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.util.retry.Retry;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkServiceException;
import software.amazon.awssdk.services.kms.model.DependencyTimeoutException;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.InvalidKeyUsageException;
import software.amazon.awssdk.services.kms.model.KeyUnavailableException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.NotFoundException;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

/**
 * Classifies KMS failures into a {@link SigningFailureReason} and decides which are worth
 * retrying (AC-10, ES-01). Lives in infrastructure because it inspects AWS SDK types.
 *
 * <p>Like {@code QtspRetryPolicy}, it walks the whole cause chain: the first cause that
 * matches a known case decides. An {@code SdkClientException} is only treated as
 * connection-level when it wraps an {@link IOException}; other client-side failures
 * (for example missing credentials) are not retried.
 */
@Slf4j
public final class KmsRetryPolicy {

    static final String ERROR_ACCESS_DENIED = "AccessDeniedException";
    static final String ERROR_THROTTLING = "ThrottlingException";

    private KmsRetryPolicy() {}

    private enum Kind {
        TRANSIENT(SigningFailureReason.SERVICE_UNAVAILABLE),
        KEY_UNUSABLE(SigningFailureReason.KEY_UNUSABLE),
        UNKNOWN(SigningFailureReason.OTHER);

        private final SigningFailureReason reason;

        Kind(SigningFailureReason reason) {
            this.reason = reason;
        }
    }

    public static SigningFailureReason classify(Throwable throwable) {
        if (throwable instanceof KmsSigningException ex) {
            return ex.getReason();
        }
        return kindOf(throwable).reason;
    }

    public static boolean isRetryable(Throwable throwable) {
        return !(throwable instanceof KmsSigningException) && kindOf(throwable) == Kind.TRANSIENT;
    }

    /**
     * Backoff retry for {@code maxRetries} retries (so {@code maxRetries + 1} attempts) over
     * retryable failures only. When retries run out the result is a
     * {@link KmsSigningException} with {@code SERVICE_UNAVAILABLE}.
     */
    public static Retry retrySpec(KmsSigningProperties properties, String operation, String keyRef) {
        int maxRetries = properties.maxRetries();
        return Retry.backoff(maxRetries, properties.initialBackoff())
                .maxBackoff(properties.maxBackoff())
                .jitter(0.5)
                .filter(KmsRetryPolicy::isRetryable)
                .doBeforeRetry(rs -> log.warn(
                        "Retrying KMS {}. keyRef={} attempt={} of {}, reason={}",
                        operation, KmsKeyRefs.forLog(keyRef), rs.totalRetries() + 1, maxRetries, describe(rs.failure())))
                .onRetryExhaustedThrow((spec, signal) -> new KmsSigningException(
                        SigningFailureReason.SERVICE_UNAVAILABLE,
                        "KMS " + operation + " unavailable after " + signal.totalRetries()
                                + " retries, last=" + describe(signal.failure()),
                        signal.failure()));
    }

    /** Wraps a failure that was not retried; a {@link KmsSigningException} is returned unchanged. */
    public static KmsSigningException toSigningException(Throwable throwable, String operation) {
        if (throwable instanceof KmsSigningException ex) {
            return ex;
        }
        SigningFailureReason reason = classify(throwable);
        return new KmsSigningException(reason,
                "KMS " + operation + " failed: reason=" + reason + ", error=" + describe(throwable),
                throwable);
    }

    /** AWS error code of the first service exception in the chain, else the class name; never the message. */
    static String describe(Throwable throwable) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            String code = errorCode(current);
            if (code != null) {
                return code;
            }
            current = current.getCause();
        }
        return throwable == null ? "n/a" : throwable.getClass().getSimpleName();
    }

    private static Kind kindOf(Throwable throwable) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            Kind kind = kindOfCause(current);
            if (kind != Kind.UNKNOWN) {
                return kind;
            }
            current = current.getCause();
        }
        return Kind.UNKNOWN;
    }

    private static Kind kindOfCause(Throwable throwable) {
        if (throwable instanceof SdkServiceException service) {
            return kindOfService(service);
        }
        boolean transientCause = throwable instanceof ApiCallTimeoutException
                || throwable instanceof ApiCallAttemptTimeoutException
                || throwable instanceof TimeoutException
                || throwable instanceof IOException;
        return transientCause ? Kind.TRANSIENT : Kind.UNKNOWN;
    }

    private static Kind kindOfService(SdkServiceException service) {
        String errorCode = errorCode(service);
        if (service instanceof DisabledException
                || service instanceof KmsInvalidStateException
                || service instanceof NotFoundException
                || service instanceof InvalidKeyUsageException
                || ERROR_ACCESS_DENIED.equals(errorCode)) {
            return Kind.KEY_UNUSABLE;
        }
        if (service.isThrottlingException()
                || ERROR_THROTTLING.equals(errorCode)
                || service instanceof KmsInternalException
                || service instanceof DependencyTimeoutException
                || service instanceof KeyUnavailableException
                || service.statusCode() >= 500) {
            return Kind.TRANSIENT;
        }
        return Kind.UNKNOWN;
    }

    private static String errorCode(Throwable throwable) {
        if (throwable instanceof AwsServiceException ase && ase.awsErrorDetails() != null) {
            return ase.awsErrorDetails().errorCode();
        }
        return null;
    }
}
