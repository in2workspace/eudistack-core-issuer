package es.in2.issuer.backend.signing.infrastructure.properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OwnKeyCertificatePropertiesTest {

    private static OwnKeyCertificateProperties at(String location) {
        return new OwnKeyCertificateProperties(location == null ? null : URI.create(location), null, null,
                Duration.ofSeconds(10));
    }

    @Test
    void s3Location_givesTheBucketAndThePrefixWithoutSlashes() {
        var properties = at("s3://certs-bucket//issuer/own-key/");

        assertThat(properties.bucket()).isEqualTo("certs-bucket");
        assertThat(properties.prefix()).isEqualTo("issuer/own-key");
    }

    @Test
    void noLocation_isAccepted() {
        assertThatCode(() -> at(null)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://certs-bucket/issuer", "certs-bucket/issuer", "s3:///issuer"})
    void locationThatIsNotAnS3Bucket_isRejected(String location) {
        assertThatThrownBy(() -> at(location)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nonPositiveTimeout_isRejected() {
        URI location = URI.create("s3://b");

        assertThatThrownBy(() -> new OwnKeyCertificateProperties(location, null, null, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
