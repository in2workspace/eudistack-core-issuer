package es.in2.issuer.backend.signing.infrastructure.s3;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletionException;
import java.util.regex.Pattern;

/**
 * {@link OwnKeyCertificatePort} over S3: the certificate of a tenant is the object
 * {@code <prefix>/<tenant>/latest/cert.pem} of the configured bucket.
 *
 * <p>A missing object is a tenant without certificate. Without {@code s3:ListBucket} S3 answers a missing
 * object with 403 instead of 404, so a refused read is reported as a missing configuration too, and
 * logged as such. Any other failure is {@code PROVIDER_UNAVAILABLE}.
 */
@Slf4j
public class S3OwnKeyCertificateAdapter implements OwnKeyCertificatePort {

    static final String CERTIFICATE_OBJECT = "latest/cert.pem";
    private static final int FORBIDDEN = 403;
    /** The tenant id becomes part of the object key: nothing that could leave its folder. */
    private static final Pattern TENANT_ID = Pattern.compile("^[a-z0-9][a-z0-9_-]{0,62}$");

    private final S3AsyncClient client;
    private final OwnKeyCertificateProperties properties;

    public S3OwnKeyCertificateAdapter(S3AsyncClient client, OwnKeyCertificateProperties properties) {
        this.client = client;
        this.properties = properties;
    }

    @Override
    public Mono<String> findCertificateChainPem(String tenant) {
        if (tenant == null || !TENANT_ID.matcher(tenant).matches()) {
            return Mono.error(new SigningException(SigningFailureReason.NO_CONFIGURATION,
                    "The tenant id cannot name an own-key certificate"));
        }
        String key = objectKey(tenant);
        // fromFuture takes a supplier so that every subscription issues a fresh read.
        return Mono.fromFuture(() -> client.getObject(GetObjectRequest.builder()
                                .bucket(properties.bucket())
                                .key(key)
                                .build(),
                        AsyncResponseTransformer.toBytes()))
                .map(response -> response.asString(StandardCharsets.US_ASCII))
                .onErrorResume(error -> isMissing(error), error -> Mono.empty())
                .onErrorMap(error -> failure(tenant, key, error));
    }

    String objectKey(String tenant) {
        String prefix = properties.prefix();
        return (prefix.isEmpty() ? "" : prefix + "/") + tenant + "/" + CERTIFICATE_OBJECT;
    }

    private static boolean isMissing(Throwable error) {
        return unwrap(error) instanceof NoSuchKeyException;
    }

    private SigningException failure(String tenant, String key, Throwable error) {
        Throwable cause = unwrap(error);
        if (cause instanceof S3Exception s3 && s3.statusCode() == FORBIDDEN) {
            log.error("Own-key certificate not readable (missing object or missing s3:GetObject) tenant={} "
                    + "bucket={} key={}", tenant, properties.bucket(), key);
            return new SigningException(SigningFailureReason.NO_CONFIGURATION,
                    "The own-key certificate of the tenant cannot be read");
        }
        log.error("Own-key certificate read failed tenant={} bucket={} key={} error={}", tenant,
                properties.bucket(), key, cause.getClass().getSimpleName());
        return new SigningException(SigningFailureReason.PROVIDER_UNAVAILABLE,
                "The own-key certificate of the tenant could not be read", cause);
    }

    private static Throwable unwrap(Throwable error) {
        return error instanceof CompletionException && error.getCause() != null ? error.getCause() : error;
    }
}
