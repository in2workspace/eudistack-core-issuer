package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.statuslist.domain.model.RevocationRequestViolation;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.statuslist.application.RevocationAuditDetails.MAX_REASON_LENGTH;

/**
 * Shape of a revocation request under the contract of EUD-247: {@code id} is a UUID and
 * {@code reason} has 1 to 280 characters. Characters are counted as code points, as JSON Schema's
 * {@code maxLength} does, so an emoji is one character and not two.
 */
public final class RevocationRequestValidator {

    public static final String ID_FIELD = "id";
    public static final String REASON_FIELD = "reason";

    private static final Pattern CANONICAL_UUID =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private RevocationRequestValidator() {
    }

    public static List<RevocationRequestViolation> validate(String issuanceId, String reason) {
        List<RevocationRequestViolation> violations = new ArrayList<>();
        if (issuanceId == null || !CANONICAL_UUID.matcher(issuanceId).matches()) {
            violations.add(new RevocationRequestViolation(ID_FIELD, "must be a UUID"));
        }
        // A reason made only of control characters is empty once sanitized for the audit trail.
        String sanitized = RevocationAuditDetails.sanitize(reason, Integer.MAX_VALUE);
        if (sanitized == null || sanitized.isBlank()) {
            violations.add(new RevocationRequestViolation(REASON_FIELD, "is required"));
        } else if (reason.codePointCount(0, reason.length()) > MAX_REASON_LENGTH) {
            violations.add(new RevocationRequestViolation(REASON_FIELD,
                    "must be at most " + MAX_REASON_LENGTH + " characters"));
        }
        return violations;
    }
}
