package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SearchIdentifierInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SubjectInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.ValidityInput;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * {@code CatalogEntryConfiguration} of the Attestation Catalogue contract: the body of a replace (PUT)
 * and, extended, of a create (POST). Every member may be missing; the validator reports what is.
 *
 * <p>{@code validity}, {@code subject} and each search identifier are closed objects in every method.
 * The top level is closed only on create: a client that reads an entry, changes it and sends it back whole
 * (with its {@code credential_configuration_id}, {@code schema_uri}, {@code created} and {@code updated})
 * must not get a 400 on replace.
 */
@Getter
@Setter
public class CatalogEntryConfigurationRequest extends UnknownFieldsCollector {

    private Boolean enabled;

    @JsonProperty("delivery_modes")
    private List<String> deliveryModes;

    private ValidityRequest validity;

    private SubjectRequest subject;

    @JsonProperty("search_identifiers")
    private List<SearchIdentifierRequest> searchIdentifiers;

    /** For a create: the unknown fields of the top level are violations. */
    public CatalogConfigurationInput toStrictInput() {
        return toInput(unknownFields());
    }

    /** For a replace: the unknown fields of the top level are ignored. */
    public CatalogConfigurationInput toInputIgnoringUnknownFields() {
        return toInput(List.of());
    }

    private CatalogConfigurationInput toInput(List<String> topLevelUnknownFields) {
        return new CatalogConfigurationInput(
                enabled,
                deliveryModes,
                validity == null ? null : validity.toInput(),
                subject == null ? null : subject.toInput(),
                searchIdentifiers == null ? null : searchIdentifiers.stream()
                        .map(identifier -> identifier == null ? null : identifier.toInput())
                        .toList(),
                topLevelUnknownFields);
    }

    @Getter
    @Setter
    public static class ValidityRequest extends UnknownFieldsCollector {

        @JsonProperty("default_days")
        private Integer defaultDays;

        @JsonProperty("requester_can_set_dates")
        private Boolean requesterCanSetDates;

        @JsonProperty("max_days")
        private Integer maxDays;

        ValidityInput toInput() {
            return new ValidityInput(defaultDays, requesterCanSetDates, maxDays, unknownFields());
        }
    }

    @Getter
    @Setter
    public static class SubjectRequest extends UnknownFieldsCollector {

        private List<List<String>> fields;

        private String separator;

        SubjectInput toInput() {
            return new SubjectInput(fields, separator, unknownFields());
        }
    }

    @Getter
    @Setter
    public static class SearchIdentifierRequest extends UnknownFieldsCollector {

        private String name;

        private List<String> field;

        SearchIdentifierInput toInput() {
            return new SearchIdentifierInput(name, field, unknownFields());
        }
    }
}
