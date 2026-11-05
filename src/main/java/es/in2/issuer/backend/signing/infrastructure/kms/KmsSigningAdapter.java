package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.function.Supplier;

/**
 * {@link KmsSigningPort} over the AWS KMS async client. SDK retries are disabled in the client;
 * retries, the per-attempt timeout and the deadline of each operation are applied here with Reactor
 * ({@link KmsRetryPolicy}, {@link KmsSigningTiming}).
 *
 * <p>The client is obtained on the first signature, on a scheduler that may block: building it resolves the
 * region, and without one the SDK may query the instance metadata endpoint until it times out. A client that
 * cannot be built fails the signature with {@code KEY_UNUSABLE}, without retries, and the next signature
 * tries again.
 */
@Slf4j
public class KmsSigningAdapter implements KmsSigningPort {

    private static final String OP_SIGN = "Sign";

    private final Supplier<KmsAsyncClient> clientFactory;
    private final KmsSigningTiming timing;
    private volatile KmsAsyncClient client;

    public KmsSigningAdapter(Supplier<KmsAsyncClient> clientFactory) {
        this(clientFactory, KmsSigningTiming.DEFAULT);
    }

    KmsSigningAdapter(Supplier<KmsAsyncClient> clientFactory, KmsSigningTiming timing) {
        this.clientFactory = clientFactory;
        this.timing = timing;
    }

    @Override
    public Mono<byte[]> sign(String keyRef, byte[] sha256Digest) {
        return client()
                .flatMap(kms -> sign(kms, keyRef, sha256Digest))
                .onErrorMap(ex -> failure(OP_SIGN, keyRef, ex));
    }

    private Mono<KmsAsyncClient> client() {
        KmsAsyncClient built = client;
        if (built != null) {
            return Mono.just(built);
        }
        return Mono.fromCallable(() -> client = clientFactory.get())
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(KmsSigningAdapter::clientUnavailable);
    }

    private Mono<byte[]> sign(KmsAsyncClient kms, String keyRef, byte[] sha256Digest) {
        // fromFuture takes a supplier so every retry resubscription issues a fresh KMS call.
        return Mono.fromFuture(() -> kms.sign(SignRequest.builder()
                        .keyId(keyRef)
                        .message(SdkBytes.fromByteArray(sha256Digest))
                        .messageType(MessageType.DIGEST)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build()))
                .timeout(timing.callTimeout())
                .map(this::validSignature)
                .retryWhen(KmsRetryPolicy.retrySpec(timing, OP_SIGN, keyRef))
                .timeout(timing.deadline(), Mono.error(() -> deadlineExceeded(OP_SIGN)));
    }

    /**
     * The client could not be built, typically because no region is configured. Not transient: the
     * configuration has to change. The root cause is logged by type and message, which carry no key ARN.
     */
    private static KmsSigningException clientUnavailable(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        log.error("KMS client could not be created: {}: {}", root.getClass().getSimpleName(), root.getMessage());
        return new KmsSigningException(SigningFailureReason.KEY_UNUSABLE,
                "KMS client could not be created: " + root.getClass().getSimpleName());
    }

    private byte[] validSignature(SignResponse response) {
        if (response.signature() == null || response.signature().asByteArrayUnsafe().length == 0) {
            throw new KmsSigningException(SigningFailureReason.INVALID_RESPONSE,
                    "KMS Sign returned an empty signature");
        }
        if (response.signingAlgorithm() != SigningAlgorithmSpec.ECDSA_SHA_256) {
            throw new KmsSigningException(SigningFailureReason.INVALID_RESPONSE,
                    "KMS Sign returned an unexpected signing algorithm: " + response.signingAlgorithmAsString());
        }
        return response.signature().asByteArray();
    }

    /** Failure of an operation cut by the deadline; the deadline sits outside the retries, so it is never retried. */
    private KmsSigningException deadlineExceeded(String operation) {
        return new KmsSigningException(SigningFailureReason.PROVIDER_UNAVAILABLE,
                "KMS " + operation + " did not complete within " + timing.deadline());
    }

    private KmsSigningException failure(String operation, String keyRef, Throwable error) {
        KmsSigningException ex = KmsRetryPolicy.toSigningException(error, operation);
        log.error("KMS {} failed. keyRef={} reason={} error={}", operation, KmsKeyRefs.forLog(keyRef),
                ex.getReason(), awsError(error));
        return ex;
    }

    /**
     * The AWS error code of a failure KMS answered, so that KEY_UNUSABLE tells a disabled or missing key
     * apart from a denied access. Never the message: it carries the key ARN. Failures raised here (empty
     * response, deadline, retries exhausted) have none; the retry warnings already log the code of each try.
     */
    private static String awsError(Throwable error) {
        return error instanceof KmsSigningException ? "n/a" : KmsRetryPolicy.describe(error);
    }
}
