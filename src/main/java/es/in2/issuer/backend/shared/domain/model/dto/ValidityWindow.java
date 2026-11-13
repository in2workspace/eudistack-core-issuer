package es.in2.issuer.backend.shared.domain.model.dto;

import java.time.Instant;
import java.util.Objects;

/**
 * The validity an issuance was asked for and accepted (EUD-254 FR-06): the credential is valid from
 * {@code validFrom} to {@code validUntil}, instead of from now for the default number of days.
 */
public record ValidityWindow(Instant validFrom, Instant validUntil) {

    public ValidityWindow {
        Objects.requireNonNull(validFrom, "validFrom");
        Objects.requireNonNull(validUntil, "validUntil");
    }
}
