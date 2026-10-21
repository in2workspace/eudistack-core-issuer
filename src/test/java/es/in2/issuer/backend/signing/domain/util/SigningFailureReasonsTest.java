package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningFailureReasonsTest {

    @Test
    void of_signingExceptionWithReason_returnsThatReason() {
        var ex = new SigningException(SigningFailureReason.NO_CONFIGURATION, "none");

        assertThat(SigningFailureReasons.of(ex)).isEqualTo(SigningFailureReason.NO_CONFIGURATION);
    }

    @Test
    void of_reasonBuriedUnderForeignWrapper_isFound() {
        var kms = new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled");
        var wrapped = new RuntimeException("wrapped by a caller", new IllegalStateException("x", kms));

        assertThat(SigningFailureReasons.of(wrapped)).isEqualTo(SigningFailureReason.KEY_UNUSABLE);
    }

    @Test
    void of_genericSigningWrapperAroundClassifiedCause_returnsCauseReason() {
        var kms = new KmsSigningException(SigningFailureReason.SERVICE_UNAVAILABLE, "throttled");
        var wrapper = new SigningException("Signing failed", kms);

        assertThat(SigningFailureReasons.of(wrapper)).isEqualTo(SigningFailureReason.SERVICE_UNAVAILABLE);
    }

    @Test
    void of_noSigningExceptionInChain_returnsOther() {
        assertThat(SigningFailureReasons.of(new RuntimeException("x", new IllegalStateException())))
                .isEqualTo(SigningFailureReason.OTHER);
    }

    @Test
    void of_nullAndCyclicChains_returnOther() {
        var a = new RuntimeException("a");
        var b = new RuntimeException("b", a);
        a.initCause(b);

        assertThat(SigningFailureReasons.of(null)).isEqualTo(SigningFailureReason.OTHER);
        assertThat(SigningFailureReasons.of(a)).isEqualTo(SigningFailureReason.OTHER);
    }
}
