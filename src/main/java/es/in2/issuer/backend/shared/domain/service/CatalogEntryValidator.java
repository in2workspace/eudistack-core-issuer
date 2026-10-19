package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException.Violation;
import es.in2.issuer.backend.shared.domain.exception.UnknownSchemaException;
import es.in2.issuer.backend.shared.domain.exception.UnsupportedBindingTypeException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SearchIdentifierInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SubjectInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.ValidityInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.catalog.CreateCatalogEntryCommand;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Validates the configuration of a catalog entry against the Attestation Catalogue contract and
 * against the schema of its credential type (EUD-266), and turns it into a {@link CatalogEntry}.
 *
 * <p>One error type per response, never a mix. First the <em>shape</em>: everything that is about the
 * format of the body (missing or malformed members, unknown fields, repeated delivery modes or
 * identifier names, a delivery mode above the schema ceiling) is reported together as
 * {@code BAD_REQUEST}, and validation stops. Then the business rules, in a fixed order:
 * {@code unknown_schema}, {@code unsupported_binding_type}, {@code field_not_in_schema},
 * {@code invalid_validity}, {@code no_delivery_mode}. The first rule with violations decides the error
 * type, and the response carries only that rule's violations.
 *
 * <p>The delivery-mode ceiling is a shape violation because the contract has no code of its own for it
 * (D8); it can only be checked once the schema is known, so a create for an unknown schema skips it.
 */
@Service
@RequiredArgsConstructor
public class CatalogEntryValidator {

    private static final Pattern IDENTIFIER_NAME = Pattern.compile("^[a-z0-9_]{1,50}$");
    private static final int MAX_SEPARATOR_LENGTH = 16;
    private static final String DEFAULT_SEPARATOR = " ";
    private static final String REQUIRED = "is required";
    private static final String UNKNOWN_FIELD = "is not a known field";
    private static final String DUPLICATED = "is duplicated";
    private static final String AT_LEAST_ONE = "must be at least 1";

    private final CredentialProfileCatalog credentialProfileCatalog;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;

    /**
     * Validates the body of a create and returns the entry to insert: {@code credential_configuration_id}
     * resolved from the schema URI, the schema URI only if it is a real one (D1), version 0.
     *
     * @throws CatalogConfigurationException for any violation; {@link UnknownSchemaException} and
     *         {@link UnsupportedBindingTypeException} for the two schema-level business codes
     */
    public CatalogEntry validateForCreate(CreateCatalogEntryCommand command) {
        String schemaUri = command.schemaUri();
        boolean hasSchemaUri = schemaUri != null && !schemaUri.isBlank();
        Optional<String> credentialConfigurationId = hasSchemaUri
                ? credentialProfileCatalog.resolveSchemaUri(schemaUri)
                : Optional.empty();

        List<Violation> shape = new ArrayList<>();
        if (!hasSchemaUri) {
            shape.add(new Violation("schema_uri", REQUIRED));
        }
        validateShape(command.configuration(), credentialConfigurationId.orElse(null), shape);
        failIfAny(shape);

        String id = credentialConfigurationId.orElseThrow(() -> new UnknownSchemaException(schemaUri));
        if (credentialProfileCatalog.bindingTypeOf(id) == BindingType.UNSUPPORTED) {
            throw new UnsupportedBindingTypeException(schemaUri);
        }
        return validateBusinessRules(assemble(id, command.configuration()));
    }

    /**
     * Validates the body of a replace of the entry {@code credentialConfigurationId}; its schema does
     * not change, so only the configuration is checked.
     *
     * @throws UnknownSchemaException if the credential type is no longer loaded
     */
    public CatalogEntry validateForReplace(String credentialConfigurationId, CatalogConfigurationInput input) {
        if (credentialProfileCatalog.getByConfigurationId(credentialConfigurationId) == null) {
            throw new UnknownSchemaException(credentialProfileCatalog.schemaUriOf(credentialConfigurationId));
        }
        List<Violation> shape = new ArrayList<>();
        validateShape(input, credentialConfigurationId, shape);
        failIfAny(shape);
        return validateBusinessRules(assemble(credentialConfigurationId, input));
    }

    /** {@code no_delivery_mode}: an entry cannot be enabled while it has no delivery mode. */
    public void validateEnabling(CatalogEntry entry) {
        if (entry.deliveryModes() == null || entry.deliveryModes().isEmpty()) {
            throw noDeliveryMode();
        }
    }

    // ---- shape -----------------------------------------------------------------

    private void validateShape(CatalogConfigurationInput input, String credentialConfigurationId, List<Violation> out) {
        unknownFields(input.unknownFields(), "", out);
        if (input.enabled() == null) {
            out.add(new Violation("enabled", REQUIRED));
        }
        validateDeliveryModes(input.deliveryModes(), credentialConfigurationId, out);
        validateValidity(input.validity(), out);
        validateSubject(input.subject(), out);
        validateSearchIdentifiers(input.searchIdentifiers(), out);
    }

    private void validateDeliveryModes(List<String> modes, String credentialConfigurationId, List<Violation> out) {
        if (modes == null) {
            out.add(new Violation("delivery_modes", REQUIRED));
            return;
        }
        Set<DeliveryMode> ceiling = credentialConfigurationId == null
                ? null
                : schemaDeliveryCeiling.resolveEligibleModes(credentialConfigurationId);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < modes.size(); i++) {
            String field = "delivery_modes[" + i + "]";
            Optional<DeliveryMode> mode = modes.get(i) == null ? Optional.empty() : DeliveryMode.fromValue(modes.get(i));
            if (mode.isEmpty()) {
                out.add(new Violation(field, "must be one of " + allDeliveryModeValues()));
            } else if (!seen.add(modes.get(i))) {
                out.add(new Violation(field, DUPLICATED));
            } else if (ceiling != null && !ceiling.contains(mode.get())) {
                out.add(new Violation(field, "is not supported by the schema"));
            }
        }
    }

    private static String allDeliveryModeValues() {
        return EnumSet.allOf(DeliveryMode.class).stream().map(m -> m.value).collect(Collectors.joining(", "));
    }

    private void validateValidity(ValidityInput validity, List<Violation> out) {
        if (validity == null) {
            out.add(new Violation("validity", REQUIRED));
            return;
        }
        unknownFields(validity.unknownFields(), "validity.", out);
        if (validity.defaultDays() == null) {
            out.add(new Violation("validity.default_days", REQUIRED));
        } else if (validity.defaultDays() < 1) {
            out.add(new Violation("validity.default_days", AT_LEAST_ONE));
        }
        if (validity.requesterCanSetDates() == null) {
            out.add(new Violation("validity.requester_can_set_dates", REQUIRED));
        }
        if (validity.maxDays() != null && validity.maxDays() < 1) {
            out.add(new Violation("validity.max_days", AT_LEAST_ONE));
        } else if (Boolean.TRUE.equals(validity.requesterCanSetDates()) && validity.maxDays() == null) {
            out.add(new Violation("validity.max_days", "is required when requester_can_set_dates is true"));
        }
    }

    private void validateSubject(SubjectInput subject, List<Violation> out) {
        if (subject == null) {
            return;
        }
        unknownFields(subject.unknownFields(), "subject.", out);
        if (subject.fields() == null) {
            out.add(new Violation("subject.fields", REQUIRED));
        } else if (subject.fields().isEmpty()) {
            out.add(new Violation("subject.fields", "must have at least one path"));
        } else {
            for (int i = 0; i < subject.fields().size(); i++) {
                validatePath(subject.fields().get(i), "subject.fields[" + i + "]", out);
            }
        }
        if (subject.separator() != null && subject.separator().length() > MAX_SEPARATOR_LENGTH) {
            out.add(new Violation("subject.separator", "must have at most " + MAX_SEPARATOR_LENGTH + " characters"));
        }
    }

    private void validateSearchIdentifiers(List<SearchIdentifierInput> identifiers, List<Violation> out) {
        if (identifiers == null) {
            return;
        }
        Set<String> names = new HashSet<>();
        for (int i = 0; i < identifiers.size(); i++) {
            SearchIdentifierInput identifier = identifiers.get(i);
            String prefix = "search_identifiers[" + i + "]";
            if (identifier == null) {
                out.add(new Violation(prefix, REQUIRED));
                continue;
            }
            unknownFields(identifier.unknownFields(), prefix + ".", out);
            if (identifier.name() == null) {
                out.add(new Violation(prefix + ".name", REQUIRED));
            } else if (!IDENTIFIER_NAME.matcher(identifier.name()).matches()) {
                out.add(new Violation(prefix + ".name", "must match " + IDENTIFIER_NAME.pattern()));
            } else if (!names.add(identifier.name())) {
                out.add(new Violation(prefix + ".name", DUPLICATED));
            }
            validatePath(identifier.field(), prefix + ".field", out);
        }
    }

    /** A claim path is required, has at least one segment, and no blank segment. */
    private void validatePath(List<String> path, String field, List<Violation> out) {
        if (path == null) {
            out.add(new Violation(field, REQUIRED));
        } else if (path.isEmpty()) {
            out.add(new Violation(field, "must have at least one segment"));
        } else {
            for (int i = 0; i < path.size(); i++) {
                if (path.get(i) == null || path.get(i).isBlank()) {
                    out.add(new Violation(field + "[" + i + "]", "must not be blank"));
                }
            }
        }
    }

    private void unknownFields(List<String> names, String prefix, List<Violation> out) {
        if (names != null) {
            names.forEach(name -> out.add(new Violation(prefix + name, UNKNOWN_FIELD)));
        }
    }

    // ---- business rules --------------------------------------------------------

    /** Builds the typed entry out of an input whose shape is already valid. */
    private CatalogEntry assemble(String credentialConfigurationId, CatalogConfigurationInput input) {
        Set<DeliveryMode> modes = input.deliveryModes().stream()
                .map(value -> DeliveryMode.fromValue(value).orElseThrow())
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(DeliveryMode.class)));
        ValidityInput validity = input.validity();
        // D9: an entry saved without a subject has an empty subject, it never goes back to the type file.
        CatalogEntry.Subject subject = input.subject() == null ? null : new CatalogEntry.Subject(
                input.subject().fields().stream().map(ClaimPath::new).toList(),
                input.subject().separator() != null ? input.subject().separator() : DEFAULT_SEPARATOR);
        List<CatalogEntry.SearchIdentifier> identifiers = input.searchIdentifiers() == null
                ? List.of()
                : input.searchIdentifiers().stream()
                        .map(i -> new CatalogEntry.SearchIdentifier(i.name(), new ClaimPath(i.field())))
                        .toList();
        return new CatalogEntry(credentialConfigurationId, realSchemaUriOf(credentialConfigurationId),
                input.enabled(), modes,
                new CatalogEntry.Validity(validity.defaultDays(), validity.requesterCanSetDates(), validity.maxDays()),
                subject, identifiers, 0, null, null);
    }

    /** Only a schema URI the type file declares is stored; the synthetic fallback never is (D1). */
    private String realSchemaUriOf(String credentialConfigurationId) {
        CredentialProfile profile = credentialProfileCatalog.getByConfigurationId(credentialConfigurationId);
        String declared = profile.schemaUri();
        return declared == null || declared.isBlank() ? null : declared;
    }

    private CatalogEntry validateBusinessRules(CatalogEntry entry) {
        List<Violation> fieldsNotInSchema = fieldsNotInSchema(entry);
        if (!fieldsNotInSchema.isEmpty()) {
            throw new CatalogConfigurationException(GlobalErrorTypes.FIELD_NOT_IN_SCHEMA.getCode(),
                    fieldsNotInSchemaDetail(entry), fieldsNotInSchema);
        }
        CatalogEntry.Validity validity = entry.validity();
        if (validity.maxDays() != null && validity.defaultDays() > validity.maxDays()) {
            throw new CatalogConfigurationException(GlobalErrorTypes.INVALID_VALIDITY.getCode(),
                    "The default validity (" + validity.defaultDays() + " days) is above the maximum ("
                            + validity.maxDays() + " days)",
                    List.of(new Violation("validity.default_days", "is above validity.max_days")));
        }
        if (entry.enabled() && entry.deliveryModes().isEmpty()) {
            throw noDeliveryMode();
        }
        return entry;
    }

    private List<Violation> fieldsNotInSchema(CatalogEntry entry) {
        Set<ClaimPath> attributes = Set.copyOf(credentialProfileCatalog.attributePaths(entry.credentialConfigurationId()));
        List<Violation> violations = new ArrayList<>();
        if (entry.subject() != null) {
            for (int i = 0; i < entry.subject().fields().size(); i++) {
                if (!attributes.contains(entry.subject().fields().get(i))) {
                    violations.add(new Violation("subject.fields[" + i + "]", "is not in the schema"));
                }
            }
        }
        for (int i = 0; i < entry.searchIdentifiers().size(); i++) {
            if (!attributes.contains(entry.searchIdentifiers().get(i).field())) {
                violations.add(new Violation("search_identifiers[" + i + "].field", "is not in the schema"));
            }
        }
        return violations;
    }

    /** {@code Field [nationalId] is not in the schema}, or its plural when several paths are wrong. */
    private String fieldsNotInSchemaDetail(CatalogEntry entry) {
        Set<ClaimPath> attributes = Set.copyOf(credentialProfileCatalog.attributePaths(entry.credentialConfigurationId()));
        List<ClaimPath> wrong = new ArrayList<>();
        if (entry.subject() != null) {
            wrong.addAll(entry.subject().fields());
        }
        entry.searchIdentifiers().forEach(identifier -> wrong.add(identifier.field()));
        List<String> paths = wrong.stream().filter(path -> !attributes.contains(path)).distinct()
                .map(ClaimPath::toString).toList();
        return paths.size() == 1
                ? "Field " + paths.getFirst() + " is not in the schema"
                : "Fields " + String.join(", ", paths) + " are not in the schema";
    }

    private static CatalogConfigurationException noDeliveryMode() {
        return new CatalogConfigurationException(GlobalErrorTypes.NO_DELIVERY_MODE.getCode(),
                "An enabled entry needs at least one delivery mode",
                List.of(new Violation("delivery_modes", "must not be empty when the entry is enabled")));
    }

    /** Throws {@code BAD_REQUEST} with the violations, if there are any. */
    private static void failIfAny(List<Violation> shape) {
        if (!shape.isEmpty()) {
            throw CatalogConfigurationException.badRequest(shape);
        }
    }
}
