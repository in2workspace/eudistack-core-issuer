package es.in2.issuer.backend.statuslist.domain.exception;

import es.in2.issuer.backend.statuslist.domain.model.RevocationRequestViolation;
import lombok.Getter;

import java.util.List;

/** The revocation request has the wrong shape; it carries the violation of each field. */
@Getter
public class InvalidRevocationRequestException extends RuntimeException {

    private final transient List<RevocationRequestViolation> violations;

    public InvalidRevocationRequestException(List<RevocationRequestViolation> violations) {
        super("The revocation request is not valid");
        this.violations = List.copyOf(violations);
    }
}
