package es.in2.issuer.backend.signing.infrastructure.kms;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class KmsKeyRefsTest {

    static Stream<Arguments> keyRefs() {
        return Stream.of(
                Arguments.of("key ARN",
                        "arn:aws:kms:eu-west-1:123456789012:key/d92e3cd4-0aba-4e8c-9ce4-cd3650de95d1",
                        "key/d92e3cd4-0aba-4e8c-9ce4-cd3650de95d1"),
                Arguments.of("alias ARN", "arn:aws:kms:eu-west-1:123456789012:alias/cgcom", "alias/cgcom"),
                Arguments.of("bare key id", "d92e3cd4-0aba-4e8c-9ce4-cd3650de95d1",
                        "d92e3cd4-0aba-4e8c-9ce4-cd3650de95d1"),
                Arguments.of("alias name", "alias/cgcom", "alias/cgcom"),
                Arguments.of("truncated ARN", "arn:aws:kms:eu-west-1:123456789012", "n/a"),
                Arguments.of("ARN without resource", "arn:aws:kms:eu-west-1:123456789012:", "n/a"),
                Arguments.of("blank", " ", "n/a"),
                Arguments.of("null", null, "n/a"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyRefs")
    void forLog_neverReturnsTheAccountOrRegion(String description, String keyRef, String expected) {
        String logged = KmsKeyRefs.forLog(keyRef);

        assertThat(logged).isEqualTo(expected)
                .doesNotContain("123456789012").doesNotContain("eu-west-1");
    }
}
