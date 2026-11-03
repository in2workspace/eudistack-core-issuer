package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * {@link KmsSigningPort} over the AWS KMS async client. SDK retries are disabled in the client;
 * retries, the per-attempt timeout and the deadline of each operation are applied here with Reactor
 * ({@link KmsRetryPolicy}).
 */
@Slf4j
public class KmsSigningAdapter implements KmsSigningPort {

    private static final String OP_SIGN = "Sign";

    private final KmsAsyncClient client;
    private final KmsSigningProperties properties;

    public KmsSigningAdapter(KmsAsyncClient client, KmsSigningProperties properties) {
        this.client = client;
        this.properties = properties;
    }

    @Override
    public Mono<byte[]> sign(String keyRef, byte[] sha256Digest) {
        // fromFuture takes a supplier so every retry resubscription issues a fresh KMS call.
        return Mono.fromFuture(() -> client.sign(SignRequest.builder()
                        .keyId(keyRef)
                        .message(SdkBytes.fromByteArray(sha256Digest))
                        .messageType(MessageType.DIGEST)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build()))
                .timeout(properties.callTimeout())
                .map(this::validSignature)
                .retryWhen(KmsRetryPolicy.retrySpec(properties, OP_SIGN, keyRef))
                .timeout(properties.deadline(), Mono.error(() -> deadlineExceeded(OP_SIGN)))
                .onErrorMap(ex -> failure(OP_SIGN, keyRef, ex));
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
                "KMS " + operation + " did not complete within " + properties.deadline());
    }

    private KmsSigningException failure(String operation, String keyRef, Throwable error) {
        KmsSigningException ex = KmsRetryPolicy.toSigningException(error, operation);
        log.error("KMS {} failed. keyRef={} reason={}", operation, KmsKeyRefs.forLog(keyRef), ex.getReason());
        return ex;
    }
}
