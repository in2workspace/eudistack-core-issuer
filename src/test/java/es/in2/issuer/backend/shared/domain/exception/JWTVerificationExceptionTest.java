package es.in2.issuer.backend.shared.domain.exception;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class JWTVerificationExceptionTest {

    @Test
    void shouldExtendRuntimeException() {
        JWTVerificationException exception = new JWTVerificationException("error");
        assertThat(exception)
                .isInstanceOf(RuntimeException.class)
                .isNotInstanceOf(org.springframework.security.core.AuthenticationException.class);
    }
}
