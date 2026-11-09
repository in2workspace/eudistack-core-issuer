package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * {@code CatalogEntry} of the Attestation Catalogue contract. Members without a value are left out:
 * the contract does not allow {@code null} for {@code subject} (an entry saved without one) nor for
 * {@code validity.max_days} (a requester that cannot set dates).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CatalogEntryResponse(
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("schema_uri") String schemaUri,
        boolean enabled,
        @JsonProperty("delivery_modes") List<String> deliveryModes,
        ValidityResponse validity,
        SubjectResponse subject,
        @JsonProperty("search_identifiers") List<SearchIdentifierResponse> searchIdentifiers,
        String created,
        String updated
) {

    /** RFC 3339 {@code date-time}: ISO 8601 with the offset and always the seconds. */
    private static final DateTimeFormatter DATE_TIME = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    /** @param entry a filled entry (see {@link CatalogEntry#isFilled()}) with a schema URI */
    public static CatalogEntryResponse from(CatalogEntry entry) {
        return new CatalogEntryResponse(
                entry.credentialConfigurationId(),
                entry.schemaUri(),
                entry.enabled(),
                entry.deliveryModes().stream().map(mode -> mode.value).sorted().toList(),
                ValidityResponse.from(entry.validity()),
                entry.subject() == null ? null : SubjectResponse.from(entry.subject()),
                entry.searchIdentifiers().stream().map(SearchIdentifierResponse::from).toList(),
                format(entry.created()),
                format(entry.updated()));
    }

    private static String format(Instant instant) {
        return instant == null ? null : DATE_TIME.format(instant.atOffset(ZoneOffset.UTC));
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ValidityResponse(
            @JsonProperty("default_days") int defaultDays,
            @JsonProperty("requester_can_set_dates") boolean requesterCanSetDates,
            @JsonProperty("max_days") Integer maxDays
    ) {
        static ValidityResponse from(CatalogEntry.Validity validity) {
            return new ValidityResponse(validity.defaultDays(), validity.requesterCanSetDates(), validity.maxDays());
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SubjectResponse(List<List<String>> fields, String separator) {
        static SubjectResponse from(CatalogEntry.Subject subject) {
            return new SubjectResponse(
                    subject.fields().stream().map(ClaimPath::segments).toList(), subject.separator());
        }
    }

    public record SearchIdentifierResponse(String name, List<String> field) {
        static SearchIdentifierResponse from(CatalogEntry.SearchIdentifier identifier) {
            return new SearchIdentifierResponse(identifier.name(), identifier.field().segments());
        }
    }
}
