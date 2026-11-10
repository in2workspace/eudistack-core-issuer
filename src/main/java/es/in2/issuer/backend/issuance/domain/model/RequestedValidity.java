package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.issuance.domain.exception.InvalidValidityException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.ValidityWindow;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

/**
 * The validity dates an issuance request asks for (EUD-254 FR-06, §5). {@code validFrom} and
 * {@code validUntil} travel in the {@code payload} but are not attributes of the subject: they are split
 * from it before it is validated against the schema, and checked against the validity of the tenant's
 * catalog entry.
 *
 * <p>The raw values are kept unparsed: when the entry does not let the requester set the dates they are
 * ignored, whatever they contain.
 */
public final class RequestedValidity {

    static final String VALID_FROM = "validFrom";
    static final String VALID_UNTIL = "validUntil";

    private static final RequestedValidity NONE = new RequestedValidity(null, null);

    private final JsonNode validFrom;
    private final JsonNode validUntil;

    private RequestedValidity(JsonNode validFrom, JsonNode validUntil) {
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }

    /** A payload without its validity dates, and the dates it carried. */
    public record Split(JsonNode payload, RequestedValidity validity) {
    }

    /** Splits {@code validFrom} and {@code validUntil} from the payload; the payload given is not changed. */
    public static Split split(JsonNode payload) {
        if (!(payload instanceof ObjectNode object) || !(object.has(VALID_FROM) || object.has(VALID_UNTIL))) {
            return new Split(payload, NONE);
        }
        ObjectNode withoutDates = object.deepCopy();
        JsonNode from = withoutDates.remove(VALID_FROM);
        JsonNode until = withoutDates.remove(VALID_UNTIL);
        return new Split(withoutDates, new RequestedValidity(present(from), present(until)));
    }

    /**
     * The window the credential is issued for, or {@code null} for the entry's default (from now for its
     * default number of days).
     *
     * <ul>
     *   <li>No entry, an entry not filled yet, or one that does not let the requester set the dates: the
     *       dates are ignored.</li>
     *   <li>Otherwise the start defaults to {@code now} and the end to the start plus the default days; the
     *       end must be after the start and the duration at most the entry's maximum.</li>
     * </ul>
     *
     * @throws InvalidValidityException when a date is not an ISO 8601 date-time, the end is not after the
     *                                  start, or the duration is above the maximum
     */
    public ValidityWindow resolve(CatalogEntry entry, Instant now) {
        if (validFrom == null && validUntil == null) {
            return null;
        }
        if (entry == null || !entry.isFilled() || !entry.validity().requesterCanSetDates()) {
            return null;
        }
        CatalogEntry.Validity validity = entry.validity();
        Instant from = validFrom != null ? parse(VALID_FROM, validFrom) : now;
        Instant until = validUntil != null ? parse(VALID_UNTIL, validUntil)
                : from.plus(Duration.ofDays(validity.defaultDays()));

        if (!until.isAfter(from)) {
            throw new InvalidValidityException("validUntil must be after validFrom");
        }
        // The catalog requires max_days whenever the requester can set the dates; without it, the
        // default is the most the entry is known to allow.
        int maxDays = validity.maxDays() != null ? validity.maxDays() : validity.defaultDays();
        if (Duration.between(from, until).compareTo(Duration.ofDays(maxDays)) > 0) {
            throw new InvalidValidityException("The validity must be at most " + maxDays + " days");
        }
        return new ValidityWindow(from, until);
    }

    private static JsonNode present(JsonNode node) {
        return node == null || node.isNull() ? null : node;
    }

    /** Never echoes the value sent: it may be any string. */
    private static Instant parse(String field, JsonNode value) {
        if (!value.isTextual()) {
            throw new InvalidValidityException(field + " must be an ISO 8601 date-time");
        }
        try {
            return OffsetDateTime.parse(value.asText()).toInstant();
        } catch (DateTimeParseException _) {
            throw new InvalidValidityException(field + " must be an ISO 8601 date-time");
        }
    }
}
