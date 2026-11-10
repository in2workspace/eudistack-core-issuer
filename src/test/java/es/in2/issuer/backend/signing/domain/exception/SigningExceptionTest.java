package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningExceptionTest {

    @Test
    void constructors_withoutReason_defaultToOther() {
        var cause = new IllegalStateException("c");

        assertThat(new SigningException("m").getReason()).isEqualTo(SigningFailureReason.OTHER);
        var withCause = new SigningException("m", cause);
        assertThat(withCause.getReason()).isEqualTo(SigningFailureReason.OTHER);
        assertThat(withCause.getCause()).isSameAs(cause);
    }

    @Test
    void constructors_withReason_keepReasonMessageAndCause() {
        var cause = new IllegalStateException("c");

        var ex = new SigningException(SigningFailureReason.CERTIFICATE_INVALID, "m", cause);

        assertThat(ex.getReason()).isEqualTo(SigningFailureReason.CERTIFICATE_INVALID);
        assertThat(ex).hasMessage("m").hasCause(cause);
        assertThat(new SigningException(SigningFailureReason.KEY_UNUSABLE, "m").getReason())
                .isEqualTo(SigningFailureReason.KEY_UNUSABLE);
    }

    @Test
    void kmsSigningException_storesReasonInBaseClass() {
        SigningException ex = new KmsSigningException(SigningFailureReason.INVALID_RESPONSE, "empty");

        assertThat(ex.getReason()).isEqualTo(SigningFailureReason.INVALID_RESPONSE);
    }
}
