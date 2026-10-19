package es.in2.issuer.backend.shared.domain.model.catalog;

import java.util.List;

/**
 * The configuration of a catalog entry exactly as a request carries it, before any validation: every
 * member may be {@code null} (missing) and delivery modes are still plain strings. Keeping it this
 * loose lets {@code CatalogEntryValidator} report every violation of the body together, including an
 * unknown delivery mode or a repeated one, which a typed model would have rejected or silently dropped
 * while deserialising. The web layer fills it from its DTOs; no web type is allowed in here.
 *
 * <p>{@code unknownFields} hold the names of the attributes the body carried that the contract does
 * not define, for the objects the contract closes. The web layer leaves the top-level list empty where
 * the contract tolerates extra attributes (PUT).
 */
public record CatalogConfigurationInput(
        Boolean enabled,
        List<String> deliveryModes,
        ValidityInput validity,
        SubjectInput subject,
        List<SearchIdentifierInput> searchIdentifiers,
        List<String> unknownFields
) {

    public record ValidityInput(Integer defaultDays, Boolean requesterCanSetDates, Integer maxDays,
                                List<String> unknownFields) {
    }

    /** {@code fields} are the paths as the body spells them; {@code separator} {@code null} = default. */
    public record SubjectInput(List<List<String>> fields, String separator, List<String> unknownFields) {
    }

    public record SearchIdentifierInput(String name, List<String> field, List<String> unknownFields) {
    }
}
