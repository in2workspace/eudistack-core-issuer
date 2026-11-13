package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException.Violation;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.model.query.PageCursor;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The query parameters of {@code GET /api/v1/issuances} (EUD-255 contract), checked for shape before
 * the permission (API-10). Every field with a problem gets its violation; none repeats the value.
 */
final class IssuanceListParameters {

    static final String LIFE_CYCLE_STATUS = "life_cycle_status";
    static final String CREDENTIAL_CONFIGURATION_ID = "credential_configuration_id";
    static final String TENANT = "tenant";
    static final String LIMIT = "limit";
    static final String CURSOR = "cursor";

    static final int CREDENTIAL_CONFIGURATION_ID_MAX_LENGTH = 100;
    static final int TENANT_MAX_LENGTH = 63;

    private IssuanceListParameters() {
    }

    static IssuanceQuery toQuery(String lifeCycleStatus, String credentialConfigurationId, String tenant,
                                 String limit, String cursor) {
        List<Violation> violations = new ArrayList<>();
        Set<CredentialStatusEnum> statuses = statuses(lifeCycleStatus, violations);
        String entry = text(credentialConfigurationId, CREDENTIAL_CONFIGURATION_ID, CREDENTIAL_CONFIGURATION_ID_MAX_LENGTH, violations);
        String tenantFilter = text(tenant, TENANT, TENANT_MAX_LENGTH, violations);
        int pageSize = limit(limit, violations);
        PageCursor pageCursor = cursor(cursor, violations);
        if (!violations.isEmpty()) {
            throw new InvalidQueryException(violations);
        }
        return new IssuanceQuery(statuses, entry, tenantFilter, pageSize, pageCursor);
    }

    /** One or more states, comma-separated; repeated parameters arrive joined by commas too. */
    private static Set<CredentialStatusEnum> statuses(String value, List<Violation> violations) {
        if (value == null) {
            return Set.of();
        }
        Set<CredentialStatusEnum> statuses = EnumSet.noneOf(CredentialStatusEnum.class);
        for (String item : value.split(",", -1)) {
            Optional<CredentialStatusEnum> status = status(item.trim());
            if (status.isEmpty()) {
                violations.add(new Violation(LIFE_CYCLE_STATUS, "must be one or more of "
                        + EnumSet.allOf(CredentialStatusEnum.class) + ", comma-separated"));
                return Set.of();
            }
            statuses.add(status.get());
        }
        return statuses;
    }

    private static Optional<CredentialStatusEnum> status(String name) {
        for (CredentialStatusEnum status : CredentialStatusEnum.values()) {
            if (status.name().equals(name)) {
                return Optional.of(status);
            }
        }
        return Optional.empty();
    }

    private static String text(String value, String field, int maxLength, List<Violation> violations) {
        if (value == null) {
            return null;
        }
        if (value.isBlank()) {
            violations.add(new Violation(field, "must not be blank"));
        } else if (value.length() > maxLength) {
            violations.add(new Violation(field, "must be at most " + maxLength + " characters"));
        }
        return value;
    }

    private static int limit(String value, List<Violation> violations) {
        if (value == null) {
            return IssuanceQuery.DEFAULT_LIMIT;
        }
        try {
            int limit = Integer.parseInt(value.trim());
            if (limit >= 1 && limit <= IssuanceQuery.MAX_LIMIT) {
                return limit;
            }
        } catch (NumberFormatException notANumber) {
            // Reported below, like an out-of-range number.
        }
        violations.add(new Violation(LIMIT, "must be an integer from 1 to " + IssuanceQuery.MAX_LIMIT));
        return IssuanceQuery.DEFAULT_LIMIT;
    }

    private static PageCursor cursor(String value, List<Violation> violations) {
        if (value == null) {
            return null;
        }
        Optional<PageCursor> cursor = PageCursor.decode(value);
        if (cursor.isEmpty()) {
            violations.add(new Violation(CURSOR, "is not a cursor of this API"));
            return null;
        }
        return cursor.get();
    }
}
