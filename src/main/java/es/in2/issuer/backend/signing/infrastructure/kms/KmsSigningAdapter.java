package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.ListResourceTagsRequest;
import software.amazon.awssdk.services.kms.model.ListResourceTagsResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.Tag;

import java.util.Objects;

/**
 * {@link KmsSigningPort} over the AWS KMS async client. SDK retries are disabled in the client;
 * retries and the per-attempt timeout are applied here with Reactor ({@link KmsRetryPolicy}).
 */
@Slf4j
public class KmsSigningAdapter implements KmsSigningPort {

    private static final String OP_SIGN = "Sign";
    private static final String OP_LIST_TAGS = "ListResourceTags";
    /** Tag set on every own-key KMS key at creation: its value is the tenant the key belongs to. */
    static final String TENANT_TAG_KEY = "Tenant";

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
                .onErrorMap(ex -> failure(OP_SIGN, keyRef, ex));
    }

    /**
     * Pages are read one after the other until KMS reports no more ({@code Truncated} / {@code NextMarker}).
     * Each page has the same per-attempt timeout and retries as {@code Sign}; a page that still fails
     * fails the whole read, so a partial list is never taken for the tags of the key.
     */
    @Override
    public Mono<String> findTenantTag(String keyRef) {
        return listTags(keyRef, null)
                .expand(page -> Boolean.TRUE.equals(page.truncated())
                        ? listTags(keyRef, page.nextMarker())
                        : Mono.empty())
                .flatMapIterable(ListResourceTagsResponse::tags)
                .filter(tag -> TENANT_TAG_KEY.equals(tag.tagKey()))
                .map(Tag::tagValue)
                .filter(Objects::nonNull)
                .next()
                .onErrorMap(ex -> failure(OP_LIST_TAGS, keyRef, ex));
    }

    private Mono<ListResourceTagsResponse> listTags(String keyRef, String marker) {
        return Mono.fromFuture(() -> client.listResourceTags(ListResourceTagsRequest.builder()
                        .keyId(keyRef)
                        .marker(marker)
                        .build()))
                .timeout(properties.callTimeout())
                .retryWhen(KmsRetryPolicy.retrySpec(properties, OP_LIST_TAGS, keyRef));
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

    private KmsSigningException failure(String operation, String keyRef, Throwable error) {
        KmsSigningException ex = KmsRetryPolicy.toSigningException(error, operation);
        log.error("KMS {} failed. keyRef={} reason={}", operation, KmsKeyRefs.forLog(keyRef), ex.getReason());
        return ex;
    }
}
