package es.in2.issuer.backend.signing.infrastructure.properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OwnKeyCertificatePropertiesTest {

    private static OwnKeyCertificateProperties at(String arn) {
        return new OwnKeyCertificateProperties(arn, null);
    }

    @Test
    void prefixArn_givesTheBucketAndThePrefixWithoutSlashes() {
        var properties = at("arn:aws:s3:::certs-bucket/issuer/own-key");

        assertThat(properties.bucket()).isEqualTo("certs-bucket");
        assertThat(properties.prefix()).isEqualTo("issuer/own-key");
    }

    @Test
    void bucketArn_givesAnEmptyPrefix() {
        var properties = at("arn:aws:s3:::certs-bucket");

        assertThat(properties.bucket()).isEqualTo("certs-bucket");
        assertThat(properties.prefix()).isEmpty();
    }

    @Test
    void arnOfAnotherPartition_isAccepted() {
        assertThat(at("arn:aws-cn:s3:::certs-bucket/issuer").bucket()).isEqualTo("certs-bucket");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  "})
    void blankArn_isNoArn(String arn) {
        assertThat(at(arn).arn()).isNull();
    }

    @Test
    void noArn_isAccepted() {
        assertThatCode(() -> at(null)).doesNotThrowAnyException();
    }

    @Test
    void noArn_hasNoBucket() {
        var properties = at(null);

        assertThatThrownBy(properties::bucket).isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "s3://certs-bucket/issuer",
            "certs-bucket/issuer",
            "arn:aws:s3:::",
            "arn:aws:s3:::/issuer",
            "arn:aws:s3:eu-west-1:123456789012:certs-bucket/issuer",
            "arn:aws:kms:::certs-bucket/issuer",
            "arn:aws:s3:::certs-bucket/*",
            "arn:aws:s3:::certs-bucket/issuer/*",
            "arn:aws:s3:::certs-bucket/iss?er",
            "arn:aws:s3:::certs-*"})
    void valueThatIsNotTheArnOfABucket_isRejected(String arn) {
        assertThatThrownBy(() -> at(arn)).isInstanceOf(IllegalArgumentException.class);
    }

}
