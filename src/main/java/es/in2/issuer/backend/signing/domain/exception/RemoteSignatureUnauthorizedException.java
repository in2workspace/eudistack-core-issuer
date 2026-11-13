package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;

import java.io.Serial;

/** The signature service refused the credentials or the authorization the Issuer presented. */
public class RemoteSignatureUnauthorizedException extends RemoteSignatureException {
    @Serial
    private static final long serialVersionUID = 1L;

    public RemoteSignatureUnauthorizedException(String message) {
        super(message);
    }
}
