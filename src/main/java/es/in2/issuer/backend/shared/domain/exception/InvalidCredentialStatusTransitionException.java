package es.in2.issuer.backend.shared.domain.exception;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;

public class InvalidCredentialStatusTransitionException extends RuntimeException {

    public InvalidCredentialStatusTransitionException(CredentialStatusEnum from, CredentialStatusEnum to) {
        super("Invalid credential status transition: " + from + " → " + to);
    }
}
