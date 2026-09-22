package es.in2.issuer.backend.shared.domain.exception;

import org.springframework.security.core.AuthenticationException;

public class JWTVerificationException extends AuthenticationException {
    public JWTVerificationException(String message) {
        super(message);
    }
}