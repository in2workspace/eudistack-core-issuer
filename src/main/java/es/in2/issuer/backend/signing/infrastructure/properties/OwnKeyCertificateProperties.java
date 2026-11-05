package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Where the own-key certificates are read from. {@code arn} is the S3 ARN of the bucket or of a prefix of it,
 * {@code arn:aws:s3:::<bucket>[/<prefix>]} ({@code S3_CERTIFICATE_ARN}, as infra provisions it): the certificate
 * of a tenant is the object {@code <prefix>/<tenant>/latest/cert.pem}. A blank value is no value. Without it the
 * Issuer reads no certificate and own-key tenants cannot sign. {@code endpoint} is only for emulators such as
 * LocalStack. {@code timeout} bounds one read, retries of the SDK included.
 */
@ConfigurationProperties(prefix = "issuer.signing.certificates")
public record OwnKeyCertificateProperties(
        String arn,
        String region,
        URI endpoint,
        @DefaultValue("10s") Duration timeout
) {
    /** An S3 ARN has neither region nor account; the partition ({@code aws}, {@code aws-cn}…) is not checked. */
    private static final Pattern S3_ARN = Pattern.compile("^arn:[a-z0-9-]+:s3:::([^/:]+)(/.*)?$");

    public OwnKeyCertificateProperties {
        Objects.requireNonNull(timeout, "issuer.signing.certificates.timeout is required");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.certificates.timeout must be positive");
        }
        if (arn != null && arn.isBlank()) {
            arn = null;
        }
        if (arn != null && !S3_ARN.matcher(arn).matches()) {
            throw new IllegalArgumentException(
                    "issuer.signing.certificates.arn must be arn:aws:s3:::<bucket>[/<prefix>]");
        }
    }

    public String bucket() {
        return parsed().group(1);
    }

    /** The prefix without leading or trailing slashes; empty when the certificates are at the root of the bucket. */
    public String prefix() {
        String path = parsed().group(2) == null ? "" : parsed().group(2);
        int start = 0;
        int end = path.length();
        while (start < end && path.charAt(start) == '/') {
            start++;
        }
        while (end > start && path.charAt(end - 1) == '/') {
            end--;
        }
        return path.substring(start, end);
    }

    private Matcher parsed() {
        if (arn == null) {
            throw new IllegalStateException("issuer.signing.certificates.arn is not set");
        }
        Matcher matcher = S3_ARN.matcher(arn);
        if (!matcher.matches()) {
            throw new IllegalStateException("issuer.signing.certificates.arn is not an S3 ARN");
        }
        return matcher;
    }
}
