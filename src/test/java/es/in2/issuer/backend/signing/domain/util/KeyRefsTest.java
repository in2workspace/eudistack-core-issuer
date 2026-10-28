package es.in2.issuer.backend.signing.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class KeyRefsTest {

    @ParameterizedTest
    @ValueSource(strings = {"arn:aws:kms:eu-west-1:000000000000:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/mrk-1234abcd"})
    void isKeyArn_fullArnOfAKmsKey_isTrue(String keyRef) {
        assertThat(KeyRefs.isKeyArn(keyRef)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"1234abcd-12ab-34cd-56ef-1234567890ab", "alias/own-key-cgcom",
            "arn:aws:kms:eu-west-1:000000000000:alias/own-key-cgcom", "arn:aws:kms:eu-west-1:0000:key/abc",
            "arn:aws:sts::000000000000:assumed-role/operation/jane", "arn:aws:kms:eu-west-1:000000000000:key/abc\n"})
    void isKeyArn_anythingElse_isFalse(String keyRef) {
        assertThat(KeyRefs.isKeyArn(keyRef)).isFalse();
    }

    @Test
    void forLog_keepsOnlyTheResourcePartOfAnArn() {
        assertThat(KeyRefs.forLog("arn:aws:kms:eu-west-1:000000000000:key/abc")).isEqualTo("key/abc");
    }
}
