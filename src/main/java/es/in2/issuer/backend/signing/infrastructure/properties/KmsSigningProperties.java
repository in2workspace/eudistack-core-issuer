package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;

/**
 * KMS own-key signing settings. {@code endpoint} is only for emulators such as LocalStack. The region comes
 * from the SDK default chain ({@code AWS_REGION}, which ECS sets), and the timeouts and retries are fixed
 * ({@code KmsSigningTiming}).
 */
@ConfigurationProperties(prefix = "issuer.signing.kms")
public record KmsSigningProperties(URI endpoint) {
}
