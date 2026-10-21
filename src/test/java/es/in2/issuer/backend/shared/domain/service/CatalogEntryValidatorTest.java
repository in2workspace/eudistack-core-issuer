package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
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
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link CatalogEntryValidator} against the credential types of {@code src/test/resources/catalog-profiles}:
 * DoctorID v1 (bound, with a real {@code schema_uri}), LEAR SD-JWT (no {@code schema_uri}), Gaia-X
 * (unbound) and a synthetic type that needs an unsupported binding.
 */
class CatalogEntryValidatorTest {

    private static final String DOCTORID = "doctorid.sd.1";
    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";
    private static final String LEAR_URI = "https://registry.eudistack.net/schemas/learcredential.employee.sd.1";
    private static final String BIOMETRIC_URI = "https://registry.eudistack.net/schemas/synthetic.biometric-binding.sd.1";
    private static final String GX_URI = "https://registry.eudistack.net/schemas/gx.labelcredential.w3c.2";

    private static final CredentialProfileRegistry REGISTRY = new CredentialProfileRegistry(
            JsonMapper.builder().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false).build(),
            new PathMatchingResourcePatternResolver(), "classpath:catalog-profiles");

    private final CatalogEntryValidator validator =
            new CatalogEntryValidator(REGISTRY, new SchemaDeliveryCeiling(REGISTRY));

    // ---- a valid body ----------------------------------------------------------

    @Test
    void validateForCreate_ofTheContractExample_returnsTheEntryToInsert() {
        CatalogEntry entry = validator.validateForCreate(create(DOCTORID_URI, doctorId()));

        assertThat(entry.credentialConfigurationId()).isEqualTo(DOCTORID);
        assertThat(entry.schemaUri()).isEqualTo(DOCTORID_URI);
        assertThat(entry.enabled()).isTrue();
        assertThat(entry.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
        assertThat(entry.validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
        assertThat(entry.subject()).isEqualTo(new CatalogEntry.Subject(
                List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "));
        assertThat(entry.searchIdentifiers()).containsExactly(
                new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("personal_administrative_number")));
        assertThat(entry.version()).isZero();
    }

    @Test
    void validateForCreate_ofATypeWithoutDeclaredSchemaUri_doesNotStoreTheSyntheticOne() {
        CatalogEntry entry = validator.validateForCreate(create(LEAR_URI, doctorId()
                .withSubject(null).withIdentifiers(List.of())));

        assertThat(entry.credentialConfigurationId()).isEqualTo("learcredential.employee.sd.1");
        assertThat(entry.schemaUri()).isNull();
    }

    @Test
    void validateForCreate_withoutSubject_leavesItEmpty() {
        CatalogEntry entry = validator.validateForCreate(create(DOCTORID_URI, doctorId().withSubject(null)));

        assertThat(entry.subject()).isNull();
    }

    @Test
    void validateForCreate_withoutSeparator_defaultsToASpace() {
        CatalogEntry entry = validator.validateForCreate(create(DOCTORID_URI, doctorId().withSubject(
                new SubjectInput(List.of(List.of("givenName")), null, null))));

        assertThat(entry.subject().separator()).isEqualTo(" ");
    }

    @Test
    void validateForCreate_aDisabledEntryMayHaveNoDeliveryMode() {
        assertThatCode(() -> validator.validateForCreate(create(DOCTORID_URI,
                doctorId().withEnabled(false).withModes(List.of())))).doesNotThrowAnyException();
    }

    @Test
    void validateForCreate_withTwoIdentifiersOfTheSameName_acceptsThem() {
        CatalogEntry entry = validator.validateForCreate(create(DOCTORID_URI, doctorId().withIdentifiers(List.of(
                identifier("colegiado", "personal_administrative_number"),
                identifier("colegiado", "medical_board")))));

        assertThat(entry.searchIdentifiers()).extracting(CatalogEntry.SearchIdentifier::name)
                .containsExactly("colegiado", "colegiado");
    }

    @Test
    void validateForReplace_returnsTheEntryOfTheGivenType() {
        CatalogEntry entry = validator.validateForReplace(DOCTORID, doctorId().withEnabled(false).toInput());

        assertThat(entry.credentialConfigurationId()).isEqualTo(DOCTORID);
        assertThat(entry.enabled()).isFalse();
    }

    // ---- the business codes (AC-04, AC-05, AC-06, AC-13) -----------------------

    static Stream<Arguments> businessCases() {
        return Stream.of(
                // AC-04: the contract example, the second identifier points at an attribute DoctorID v1 lacks
                Arguments.of("AC-04 identifier field", DOCTORID_URI,
                        (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                                identifier("colegiado", "personal_administrative_number"),
                                identifier("dni", "nationalId"))),
                        "field_not_in_schema", "Field [nationalId] is not in the schema",
                        List.of("search_identifiers[1].field")),
                Arguments.of("AC-04 subject field", DOCTORID_URI,
                        (UnaryOperator<Input>) in -> in.withSubject(new SubjectInput(
                                List.of(List.of("givenName"), List.of("registrationNumber")), " ", null)),
                        "field_not_in_schema", "Field [registrationNumber] is not in the schema",
                        List.of("subject.fields[1]")),
                Arguments.of("AC-04 several fields", DOCTORID_URI,
                        (UnaryOperator<Input>) in -> in
                                .withSubject(new SubjectInput(List.of(List.of("firstName")), " ", null))
                                .withIdentifiers(List.of(identifier("dni", "nationalId"))),
                        "field_not_in_schema", "Fields [firstName], [nationalId] are not in the schema",
                        List.of("subject.fields[0]", "search_identifiers[0].field")),
                // AC-05
                Arguments.of("AC-05 default above maximum", DOCTORID_URI,
                        (UnaryOperator<Input>) in -> in.withValidity(new ValidityInput(400, true, 365, null)),
                        "invalid_validity", "The default validity (400 days) is above the maximum (365 days)",
                        List.of("validity.default_days")),
                // AC-06
                Arguments.of("AC-06 enabled without modes", DOCTORID_URI,
                        (UnaryOperator<Input>) in -> in.withModes(List.of()),
                        "no_delivery_mode", "An enabled entry needs at least one delivery mode",
                        List.of("delivery_modes")),
                // AC-13
                Arguments.of("AC-13 unsupported binding (biometric)", BIOMETRIC_URI,
                        (UnaryOperator<Input>) in -> in.withSubject(null).withIdentifiers(List.of()).withModes(List.of("email")),
                        "unsupported_binding_type",
                        "The schema '" + BIOMETRIC_URI + "' requires claim or biometric binding; only key and none are supported",
                        List.of("schema_uri")),
                Arguments.of("unknown schema", "https://registry.eudistack.net/schemas/nobody/1.0.0/dc+sd-jwt",
                        (UnaryOperator<Input>) in -> in,
                        "unknown_schema",
                        "The schema 'https://registry.eudistack.net/schemas/nobody/1.0.0/dc+sd-jwt' does not exist "
                                + "or is not available to the tenant",
                        List.of("schema_uri")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("businessCases")
    void validateForCreate_withABusinessViolation_isRejectedWithItsCode(
            String name, String schemaUri, UnaryOperator<Input> change,
            String code, String detail, List<String> fields) {
        CatalogConfigurationException thrown = catchBusiness(() ->
                validator.validateForCreate(create(schemaUri, change.apply(doctorId()))));

        assertThat(thrown.code()).isEqualTo(code);
        assertThat(thrown.getMessage()).isEqualTo(detail);
        assertThat(thrown.violations()).extracting(Violation::field).containsExactlyElementsOf(fields);
    }

    @Test
    void validateForCreate_unsupportedBindingType_isItsOwnException() {
        assertThatThrownBy(() -> validator.validateForCreate(create(BIOMETRIC_URI,
                doctorId().withSubject(null).withIdentifiers(List.of()).withModes(List.of("email")))))
                .isInstanceOf(UnsupportedBindingTypeException.class);
    }

    @Test
    void validateForCreate_unknownSchema_isItsOwnException() {
        assertThatThrownBy(() -> validator.validateForCreate(create("https://example.org/nope", doctorId())))
                .isInstanceOf(UnknownSchemaException.class);
    }

    @Test
    void validateForReplace_withAFieldNotInTheSchema_isRejected() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForReplace(DOCTORID,
                doctorId().withIdentifiers(List.of(identifier("dni", "nationalId"))).toInput()));

        assertThat(thrown.code()).isEqualTo("field_not_in_schema");
        assertThat(thrown.violations()).extracting(Violation::field).containsExactly("search_identifiers[0].field");
    }

    @Test
    void validateForReplace_ofATypeThatIsNoLongerLoaded_isRejectedAsUnknownSchema() {
        assertThatThrownBy(() -> validator.validateForReplace("removed.type.1", doctorId().toInput()))
                .isInstanceOf(UnknownSchemaException.class);
    }

    @Test
    void validateEnabling_ofAnEntryWithoutModes_isRejected() {
        CatalogEntry entry = new CatalogEntry(DOCTORID, null, false, Set.of(),
                new CatalogEntry.Validity(365, false, null), null, List.of(), 3, null, null);

        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateEnabling(entry));

        assertThat(thrown.code()).isEqualTo("no_delivery_mode");
    }

    // ---- the shape (BAD_REQUEST) -----------------------------------------------

    static Stream<Arguments> shapeCases() {
        return Stream.of(
                Arguments.of("unknown top-level field", (UnaryOperator<Input>) in -> in.withUnknown(List.of("colour")),
                        List.of("colour")),
                Arguments.of("unknown field in validity", (UnaryOperator<Input>) in -> in.withValidity(
                        new ValidityInput(365, false, null, List.of("weeks"))), List.of("validity.weeks")),
                Arguments.of("unknown field in subject", (UnaryOperator<Input>) in -> in.withSubject(
                        new SubjectInput(List.of(List.of("givenName")), " ", List.of("glue"))), List.of("subject.glue")),
                Arguments.of("unknown field in an identifier", (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                        new SearchIdentifierInput("colegiado", List.of("personal_administrative_number"), List.of("x")))),
                        List.of("search_identifiers[0].x")),
                Arguments.of("missing enabled", (UnaryOperator<Input>) in -> in.withEnabled(null), List.of("enabled")),
                Arguments.of("missing delivery_modes", (UnaryOperator<Input>) in -> in.withModes(null),
                        List.of("delivery_modes")),
                Arguments.of("missing validity", (UnaryOperator<Input>) in -> in.withValidity(null), List.of("validity")),
                Arguments.of("missing default_days", (UnaryOperator<Input>) in -> in.withValidity(
                        new ValidityInput(null, false, null, null)), List.of("validity.default_days")),
                Arguments.of("missing requester_can_set_dates", (UnaryOperator<Input>) in -> in.withValidity(
                        new ValidityInput(365, null, null, null)), List.of("validity.requester_can_set_dates")),
                Arguments.of("delivery mode outside email, ui, direct", (UnaryOperator<Input>) in -> in.withModes(
                        List.of("email", "carrier-pigeon")), List.of("delivery_modes[1]")),
                Arguments.of("repeated delivery mode (uniqueItems)", (UnaryOperator<Input>) in -> in.withModes(
                        List.of("email", "ui", "email")), List.of("delivery_modes[2]")),
                Arguments.of("delivery mode above the schema ceiling (D8)", (UnaryOperator<Input>) in -> in.withModes(
                        List.of("email", "direct")), List.of("delivery_modes[1]")),
                Arguments.of("default_days below 1", (UnaryOperator<Input>) in -> in.withValidity(
                        new ValidityInput(0, false, null, null)), List.of("validity.default_days")),
                Arguments.of("max_days below 1", (UnaryOperator<Input>) in -> in.withValidity(
                        new ValidityInput(1, false, 0, null)), List.of("validity.max_days")),
                Arguments.of("requester dates without max_days", (UnaryOperator<Input>) in -> in.withValidity(
                        new ValidityInput(365, true, null, null)), List.of("validity.max_days")),
                Arguments.of("subject without fields", (UnaryOperator<Input>) in -> in.withSubject(
                        new SubjectInput(null, " ", null)), List.of("subject.fields")),
                Arguments.of("subject with empty fields (minItems)", (UnaryOperator<Input>) in -> in.withSubject(
                        new SubjectInput(List.of(), " ", null)), List.of("subject.fields")),
                Arguments.of("subject with an empty path (minItems)", (UnaryOperator<Input>) in -> in.withSubject(
                        new SubjectInput(List.of(List.of()), " ", null)), List.of("subject.fields[0]")),
                Arguments.of("subject path with a blank segment", (UnaryOperator<Input>) in -> in.withSubject(
                        new SubjectInput(List.of(List.of("givenName", " ")), " ", null)),
                        List.of("subject.fields[0][1]")),
                Arguments.of("subject separator too long", (UnaryOperator<Input>) in -> in.withSubject(
                        new SubjectInput(List.of(List.of("givenName")), "12345678901234567", null)),
                        List.of("subject.separator")),
                Arguments.of("identifier name outside the pattern", (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                        identifier("Colegiado", "personal_administrative_number"))), List.of("search_identifiers[0].name")),
                Arguments.of("identifier name longer than 50", (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                        identifier("a".repeat(51), "personal_administrative_number"))), List.of("search_identifiers[0].name")),
                Arguments.of("identifier without name", (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                        identifier(null, "personal_administrative_number"))), List.of("search_identifiers[0].name")),
                Arguments.of("identifier with an empty path (minItems)", (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                        new SearchIdentifierInput("colegiado", List.of(), null))), List.of("search_identifiers[0].field")),
                Arguments.of("identifier without a path", (UnaryOperator<Input>) in -> in.withIdentifiers(List.of(
                        new SearchIdentifierInput("colegiado", null, null))), List.of("search_identifiers[0].field")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("shapeCases")
    void validateForCreate_withAShapeViolation_isABadRequest(String name, UnaryOperator<Input> change, List<String> fields) {
        CatalogConfigurationException thrown = catchBusiness(() ->
                validator.validateForCreate(create(DOCTORID_URI, change.apply(doctorId()))));

        assertThat(thrown.code()).isEqualTo("BAD_REQUEST");
        assertThat(thrown.violations()).extracting(Violation::field).containsExactlyElementsOf(fields);
    }

    @Test
    void validateForCreate_withoutSchemaUri_isABadRequest() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(create(null, doctorId())));

        assertThat(thrown.code()).isEqualTo("BAD_REQUEST");
        assertThat(thrown.violations()).extracting(Violation::field).containsExactly("schema_uri");
    }

    @Test
    void validateForCreate_reportsEveryShapeViolationTogether() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(create(DOCTORID_URI,
                doctorId().withEnabled(null).withModes(List.of("ui", "ui", "mail")).withUnknown(List.of("colour")))));

        assertThat(thrown.violations()).extracting(Violation::field)
                .containsExactly("colour", "enabled", "delivery_modes[1]", "delivery_modes[2]");
    }

    @Test
    void validateForReplace_withAModeAboveTheCeiling_isABadRequest() {
        CatalogConfigurationException thrown = catchBusiness(() ->
                validator.validateForReplace(DOCTORID, doctorId().withModes(List.of("direct")).toInput()));

        assertThat(thrown.code()).isEqualTo("BAD_REQUEST");
        assertThat(thrown.violations()).extracting(Violation::field).containsExactly("delivery_modes[0]");
    }

    @Test
    void validateForCreate_aModeThatNeedsTheSchema_isAcceptedWhereTheSchemaAllowsIt() {
        CatalogEntry entry = validator.validateForCreate(create(GX_URI, doctorId().withModes(List.of("direct", "email"))
                .withSubject(new SubjectInput(List.of(List.of("credentialSubject", "id")), ":", null))
                .withIdentifiers(List.of())));

        assertThat(entry.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.DIRECT, DeliveryMode.EMAIL);
    }

    // ---- one error type per response -------------------------------------------

    @Test
    void validateForCreate_withFieldNotInSchemaAndInvalidValidity_answersFieldNotInSchemaOnly() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(create(DOCTORID_URI,
                doctorId().withIdentifiers(List.of(identifier("dni", "nationalId")))
                        .withValidity(new ValidityInput(400, true, 365, null)))));

        assertThat(thrown.code()).isEqualTo("field_not_in_schema");
        assertThat(thrown.violations()).extracting(Violation::field).containsExactly("search_identifiers[0].field");
    }

    @Test
    void validateForCreate_withInvalidValidityAndNoDeliveryMode_answersInvalidValidityOnly() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(create(DOCTORID_URI,
                doctorId().withModes(List.of()).withValidity(new ValidityInput(400, true, 365, null)))));

        assertThat(thrown.code()).isEqualTo("invalid_validity");
    }

    @Test
    void validateForCreate_withAShapeErrorAndABusinessError_answersBadRequest() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(create(DOCTORID_URI,
                doctorId().withIdentifiers(List.of(identifier("dni", "nationalId")))
                        .withEnabled(null)
                        .withValidity(new ValidityInput(400, true, 365, null)))));

        assertThat(thrown.code()).isEqualTo("BAD_REQUEST");
        assertThat(thrown.violations()).extracting(Violation::field).containsExactly("enabled");
    }

    @Test
    void validateForCreate_withUnknownSchemaAndShapeError_answersBadRequest() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(
                create("https://example.org/nope", doctorId().withEnabled(null))));

        assertThat(thrown.code()).isEqualTo("BAD_REQUEST");
    }

    @Test
    void validateForCreate_withUnknownSchemaAndAnythingElseWrong_answersUnknownSchema() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(
                create("https://example.org/nope", doctorId().withValidity(new ValidityInput(400, true, 365, null)))));

        assertThat(thrown.code()).isEqualTo("unknown_schema");
    }

    @Test
    void validateForCreate_withUnsupportedBindingAndFieldNotInSchema_answersUnsupportedBinding() {
        CatalogConfigurationException thrown = catchBusiness(() -> validator.validateForCreate(create(BIOMETRIC_URI,
                doctorId().withModes(List.of("email")))));

        assertThat(thrown.code()).isEqualTo("unsupported_binding_type");
    }

    // ---- helpers ---------------------------------------------------------------

    private static CatalogConfigurationException catchBusiness(Runnable action) {
        try {
            action.run();
        } catch (CatalogConfigurationException e) {
            return e;
        }
        throw new AssertionError("Expected a CatalogConfigurationException");
    }

    private static CreateCatalogEntryCommand create(String schemaUri, Input input) {
        return new CreateCatalogEntryCommand(schemaUri, input.toInput());
    }

    private static SearchIdentifierInput identifier(String name, String... path) {
        return new SearchIdentifierInput(name, List.of(path), null);
    }

    /** The DoctorID v1 example of the contract. */
    private static Input doctorId() {
        return new Input(true, List.of("email", "ui"), new ValidityInput(36500, false, null, null),
                new SubjectInput(List.of(List.of("givenName"), List.of("familyName")), " ", null),
                List.of(identifier("colegiado", "personal_administrative_number")), null);
    }

    /** A mutable-by-copy view of {@link CatalogConfigurationInput}, to tweak one member per case. */
    private record Input(Boolean enabled, List<String> modes, ValidityInput validity, SubjectInput subject,
                         List<SearchIdentifierInput> identifiers, List<String> unknown) {

        Input withEnabled(Boolean value) {
            return new Input(value, modes, validity, subject, identifiers, unknown);
        }

        Input withModes(List<String> value) {
            return new Input(enabled, value, validity, subject, identifiers, unknown);
        }

        Input withValidity(ValidityInput value) {
            return new Input(enabled, modes, value, subject, identifiers, unknown);
        }

        Input withSubject(SubjectInput value) {
            return new Input(enabled, modes, validity, value, identifiers, unknown);
        }

        Input withIdentifiers(List<SearchIdentifierInput> value) {
            return new Input(enabled, modes, validity, subject, value, unknown);
        }

        Input withUnknown(List<String> value) {
            return new Input(enabled, modes, validity, subject, identifiers, value);
        }

        CatalogConfigurationInput toInput() {
            return new CatalogConfigurationInput(enabled, modes, validity, subject, identifiers, unknown);
        }
    }
}
