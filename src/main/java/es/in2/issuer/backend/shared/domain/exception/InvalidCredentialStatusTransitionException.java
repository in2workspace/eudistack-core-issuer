package es.in2.issuer.backend.shared.domain.exception;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;

public class InvalidCredentialStatusTransitionException extends RuntimeException {

    private final CredentialStatusEnum from;

    public InvalidCredentialStatusTransitionException(CredentialStatusEnum from, CredentialStatusEnum to) {
        super("Invalid credential status transition: " + from + " → " + to);
        this.from = from;
    }

    public CredentialStatusEnum getFrom() {
        return from;
    }
}
