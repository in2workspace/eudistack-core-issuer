package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates DoctorID payloads against the real vendored {@code doctorid.sd.1.json} schema
 * ({@code dev-tools/credentials/profiles}), not against a handcrafted fixture, so a drift between the
 * schema synced from platform-dev and the validation rules shows up here.
 */
@DisplayName("PayloadSchemaValidatorImpl against the real doctorid.sd.1 schema")
class PayloadSchemaValidatorImplDoctorIdSchemaTest {

    private static final String CONFIG_ID = "doctorid.sd.1";

    private static final String VALID_PAYLOAD = """
            {
              "givenName": "María",
              "familyName": "García López",
              "personal_administrative_number": "282801234",
              "medical_board": ["COM Barcelona"],
              "medical_speciality": ["Internal Medicine"],
              "legally_entitled": true
            }
            """;

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    private PayloadSchemaValidatorImpl validator;

    @BeforeEach
    void setUp() {
        CredentialProfileRegistry registry = new CredentialProfileRegistry(
                objectMapper, new PathMatchingResourcePatternResolver(), "file:dev-tools/credentials/profiles");
        validator = new PayloadSchemaValidatorImpl(registry);
    }

    private ObjectNode payload() throws Exception {
        return (ObjectNode) objectMapper.readTree(VALID_PAYLOAD);
    }

    private void assertRejectedWithViolation(JsonNode payload, String expectedFragment) {
        StepVerifier.create(validator.validate(CONFIG_ID, payload))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(PayloadValidationException.class);
                    assertThat(((PayloadValidationException) error).getViolations())
                            .anyMatch(v -> v.field().contains(expectedFragment)
                                    || v.message().contains(expectedFragment));
                })
                .verify();
    }

    @Test
    @DisplayName("validate_allMandatoryAttributes_completesSuccessfully")
    void validate_allMandatoryAttributes_completesSuccessfully() throws Exception {
        // Arrange
        ObjectNode payload = payload();

        // Act
        var result = validator.validate(CONFIG_ID, payload);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    @DisplayName("validate_undeclaredBusinessAttribute_completesSuccessfully")
    void validate_undeclaredBusinessAttribute_completesSuccessfully() throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.put("externalReference", "REF-2026-001");

        // Act
        var result = validator.validate(CONFIG_ID, payload);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @ParameterizedTest
    @ValueSource(strings = {"givenName", "familyName", "personal_administrative_number", "medical_speciality"})
    @DisplayName("validate_mandatoryAttributeMissing_rejectsWithPayloadValidationException")
    void validate_mandatoryAttributeMissing_rejectsWithPayloadValidationException(String attribute) throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.remove(attribute);

        // Act
        var result = validator.validate(CONFIG_ID, payload);

        // Assert
        StepVerifier.create(result)
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(PayloadValidationException.class);
                    assertThat(((PayloadValidationException) error).getViolations())
                            .anyMatch(v -> v.message().contains(attribute));
                })
                .verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {"123", "28280123", "2828012345", "28280123A"})
    @DisplayName("validate_registrationNumberIsNotNineDigits_rejectsWithPayloadValidationException")
    void validate_registrationNumberIsNotNineDigits_rejectsWithPayloadValidationException(String number) throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.put("personal_administrative_number", number);

        // Act & Assert
        assertRejectedWithViolation(payload, "personal_administrative_number");
    }

    @Test
    @DisplayName("validate_specialityOutsideTheAllowedList_rejectsWithPayloadValidationException")
    void validate_specialityOutsideTheAllowedList_rejectsWithPayloadValidationException() throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.putArray("medical_speciality").add("Astrology");

        // Act & Assert
        assertRejectedWithViolation(payload, "medical_speciality");
    }

    @Test
    @DisplayName("validate_legallyEntitledIsNotBoolean_rejectsWithPayloadValidationException")
    void validate_legallyEntitledIsNotBoolean_rejectsWithPayloadValidationException() throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.put("legally_entitled", "yes");

        // Act & Assert
        assertRejectedWithViolation(payload, "legally_entitled");
    }

    @Test
    @DisplayName("validate_medicalBoardIsNotAnArray_rejectsWithPayloadValidationException")
    void validate_medicalBoardIsNotAnArray_rejectsWithPayloadValidationException() throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.put("medical_board", "COM Barcelona");

        // Act & Assert
        assertRejectedWithViolation(payload, "medical_board");
    }

    @ParameterizedTest
    @ValueSource(strings = {"iss", "vct", "cnf", "status"})
    @DisplayName("validate_additionalAttributeUsesReservedName_rejectsWithPayloadValidationException")
    void validate_additionalAttributeUsesReservedName_rejectsWithPayloadValidationException(String reservedName)
            throws Exception {
        // Arrange
        ObjectNode payload = payload();
        payload.put(reservedName, "forged");

        // Act & Assert
        assertRejectedWithViolation(payload, "$." + reservedName);
    }
}
