package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.issuance.domain.exception.InvalidValidityException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.ValidityWindow;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** EUD-254 FR-06, §5 (EUD-268): validity dates split from the payload and checked against the catalog entry. */
class RequestedValidityTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-10T10:00:00Z");

    private static CatalogEntry entry(int defaultDays, boolean requesterCanSetDates, Integer maxDays) {
        return new CatalogEntry("type.sd.1", null, true, Set.of(DeliveryMode.EMAIL),
                new CatalogEntry.Validity(defaultDays, requesterCanSetDates, maxDays), null, List.of(), 0, null, null);
    }

    private static final CatalogEntry ALLOWS_DATES = entry(30, true, 365);
    private static final CatalogEntry FIXED_DATES = entry(30, false, null);

    private static RequestedValidity requested(String validFrom, String validUntil) {
        ObjectNode payload = MAPPER.createObjectNode().put("name", "x");
        if (validFrom != null) {
            payload.put("validFrom", validFrom);
        }
        if (validUntil != null) {
            payload.put("validUntil", validUntil);
        }
        return RequestedValidity.split(payload).validity();
    }

    // --- split ---

    @Test
    void splitRemovesTheDatesWithoutChangingTheGivenPayload() {
        ObjectNode payload = MAPPER.createObjectNode().put("name", "x")
                .put("validFrom", "2026-12-01T00:00:00Z").put("validUntil", "2027-01-01T00:00:00Z");

        RequestedValidity.Split split = RequestedValidity.split(payload);

        assertEquals(MAPPER.createObjectNode().put("name", "x"), split.payload());
        assertTrue(payload.has("validFrom"), "the payload given is not changed");
    }

    @Test
    void splitKeepsAPayloadWithoutDatesAsIs() {
        JsonNode payload = MAPPER.createObjectNode().put("name", "x");

        RequestedValidity.Split split = RequestedValidity.split(payload);

        assertSame(payload, split.payload());
        assertNull(split.validity().resolve(ALLOWS_DATES, NOW));
    }

    // --- the entry does not let the requester set the dates: ignored ---

    @Test
    void datesAreIgnoredWhenTheEntryDoesNotAllowThem() {
        assertNull(requested("2026-12-01T00:00:00Z", "2030-01-01T00:00:00Z").resolve(FIXED_DATES, NOW));
    }

    @Test
    void evenMalformedDatesAreIgnoredWhenTheEntryDoesNotAllowThem() {
        assertNull(requested("not-a-date", "neither").resolve(FIXED_DATES, NOW));
    }

    @Test
    void datesAreIgnoredWithoutAnEntryOrWithAnEntryNotFilledYet() {
        RequestedValidity validity = requested("2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z");
        CatalogEntry notFilled = new CatalogEntry("type.sd.1", null, true, null, null, null, List.of(), 0, null, null);

        assertNull(validity.resolve(null, NOW));
        assertNull(validity.resolve(notFilled, NOW));
    }

    // --- the entry allows them ---

    @Test
    void bothDatesWithinTheMaximumAreTheWindow() {
        ValidityWindow window = requested("2026-12-01T00:00:00Z", "2027-06-01T00:00:00+02:00").resolve(ALLOWS_DATES, NOW);

        assertEquals(new ValidityWindow(Instant.parse("2026-12-01T00:00:00Z"), Instant.parse("2027-05-31T22:00:00Z")),
                window);
    }

    @Test
    void aDurationOfExactlyTheMaximumIsAccepted() {
        Instant from = Instant.parse("2026-12-01T00:00:00Z");
        ValidityWindow window = requested(from.toString(), from.plus(Duration.ofDays(365)).toString())
                .resolve(ALLOWS_DATES, NOW);

        assertEquals(from.plus(Duration.ofDays(365)), window.validUntil());
    }

    @Test
    void onlyTheStartEndsAfterTheDefaultDays() {
        ValidityWindow window = requested("2026-12-01T00:00:00Z", null).resolve(ALLOWS_DATES, NOW);

        assertEquals(Instant.parse("2026-12-31T00:00:00Z"), window.validUntil());
    }

    @Test
    void onlyTheEndStartsNow() {
        ValidityWindow window = requested(null, "2027-01-01T00:00:00Z").resolve(ALLOWS_DATES, NOW);

        assertEquals(NOW, window.validFrom());
    }

    @Test
    void aDurationAboveTheMaximumIsInvalid() {
        RequestedValidity validity = requested("2026-12-01T00:00:00Z", "2027-12-02T00:00:00Z");

        InvalidValidityException ex = assertThrows(InvalidValidityException.class,
                () -> validity.resolve(ALLOWS_DATES, NOW));
        assertEquals("The validity must be at most 365 days", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"2026-12-01T00:00:00Z", "2026-11-30T00:00:00Z"})
    void anEndNotAfterTheStartIsInvalid(String validUntil) {
        RequestedValidity validity = requested("2026-12-01T00:00:00Z", validUntil);

        assertThrows(InvalidValidityException.class, () -> validity.resolve(ALLOWS_DATES, NOW));
    }

    @Test
    void onlyAnEndBeforeNowIsInvalid() {
        RequestedValidity validity = requested(null, "2026-01-01T00:00:00Z");

        assertThrows(InvalidValidityException.class, () -> validity.resolve(ALLOWS_DATES, NOW));
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-date", "2026-12-01", "2026-12-01T00:00:00", "01/12/2026"})
    void aDateThatIsNotAnIso8601DateTimeIsInvalidWithoutEchoingIt(String value) {
        RequestedValidity validity = requested(value, null);

        InvalidValidityException ex = assertThrows(InvalidValidityException.class,
                () -> validity.resolve(ALLOWS_DATES, NOW));
        assertEquals("validFrom must be an ISO 8601 date-time", ex.getMessage());
    }

    @Test
    void aDateThatIsNotAStringIsInvalid() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("validUntil", 1767225600);
        RequestedValidity validity = RequestedValidity.split(payload).validity();

        assertThrows(InvalidValidityException.class, () -> validity.resolve(ALLOWS_DATES, NOW));
    }

    @Test
    void nullDatesAreTreatedAsAbsent() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.putNull("validFrom");
        payload.putNull("validUntil");

        RequestedValidity.Split split = RequestedValidity.split(payload);

        assertEquals(MAPPER.createObjectNode(), split.payload());
        assertNull(split.validity().resolve(ALLOWS_DATES, NOW));
    }
}
