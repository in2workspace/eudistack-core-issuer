package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Where the own-key certificates are read from. {@code location} is {@code s3://<bucket>/<prefix>}: the
 * certificate of a tenant is the object {@code <prefix>/<tenant>/latest}. Without it the Issuer reads no
 * certificate and own-key tenants cannot sign. {@code endpoint} is only for emulators such as LocalStack.
 * {@code timeout} bounds one read, retries of the SDK included.
 */
@ConfigurationProperties(prefix = "issuer.signing.certificates")
public record OwnKeyCertificateProperties(
        URI location,
        String region,
        URI endpoint,
        @DefaultValue("10s") Duration timeout
) {
    private static final String S3_SCHEME = "s3";

    public OwnKeyCertificateProperties {
        Objects.requireNonNull(timeout, "issuer.signing.certificates.timeout is required");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.certificates.timeout must be positive");
        }
        if (location != null && (!S3_SCHEME.equals(location.getScheme()) || location.getHost() == null)) {
            throw new IllegalArgumentException("issuer.signing.certificates.location must be s3://<bucket>/<prefix>");
        }
    }

    public String bucket() {
        return location.getHost();
    }

    /** The prefix without leading or trailing slashes; empty when the certificates are at the root of the bucket. */
    public String prefix() {
        String path = location.getPath() == null ? "" : location.getPath();
        return path.replaceAll("^/+|/+$", "");
    }
}
