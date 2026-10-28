package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import reactor.test.StepVerifier;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IssuancePayloadNormalizerImplTest {

    private static final String EMPLOYEE_W3C = "learcredential.employee.w3c.4";
    private static final String EMPLOYEE_SD = "learcredential.employee.sd.1";
    private static final String MACHINE_W3C = "learcredential.machine.w3c.3";
    private static final String PID = "eu.europa.ec.eudi.pid.1";

    private static final String SERIAL_NUMBER = "/mandator/serialNumber";
    private static final String ORGANIZATION_IDENTIFIER = "/mandator/organizationIdentifier";

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    private SimpleMeterRegistry meterRegistry;
    private IssuancePayloadNormalizerImpl normalizer;
    private PayloadSchemaValidatorImpl validator;

    @BeforeEach
    void setUp() {
        CredentialProfileRegistry registry = new CredentialProfileRegistry(
                objectMapper, new PathMatchingResourcePatternResolver(), "file:dev-tools/credentials/profiles");
        PayloadSubschemaResolver resolver = new PayloadSubschemaResolver(registry);
        meterRegistry = new SimpleMeterRegistry();
        normalizer = new IssuancePayloadNormalizerImpl(resolver, new IssuanceMetrics(meterRegistry));
        validator = new PayloadSchemaValidatorImpl(resolver);
    }

    private static String mandate(String mandatee, String mandator, String power) {
        return "{ \"mandatee\": " + mandatee + ", \"mandator\": " + mandator + ", \"power\": " + power + " }";
    }

    private static String employeeMandate(String mandatee, String mandator) {
        return mandate(mandatee, mandator, "[{ \"function\": \"Onboarding\", \"domain\": \"localhost\" }]");
    }

    private static final String EMPLOYEE_MANDATEE =
            "{ \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"email\": \"jane.doe@example.com\" }";
    private static final String MACHINE_MANDATEE = "{ \"domain\": \"machine.example.com\" }";

    private static String mandatorWith(String optionalClaim) {
        return "{ \"organizationIdentifier\": \"VATES-A00000000\", \"country\": \"ES\", " + optionalClaim + " }";
    }

    private static final String PID_BASE = """
            "given_name": "Maria", "family_name": "Garcia", "birth_date": "1990-05-14",
            "birth_place": "Madrid", "nationality": "ES", "issuance_date": "2026-08-03",
            "expiry_date": "2031-08-03", "issuing_authority": "Authority", "issuing_country": "ES\"""";

    private JsonNode json(String content) throws Exception {
        return objectMapper.readTree(content);
    }

    static Stream<Arguments> removedOptionalValues() {
        return Stream.of(
                Arguments.of(EMPLOYEE_W3C, employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": null")),
                        SERIAL_NUMBER, ORGANIZATION_IDENTIFIER),
                Arguments.of(EMPLOYEE_SD, employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": \"\"")),
                        SERIAL_NUMBER, ORGANIZATION_IDENTIFIER),
                Arguments.of(MACHINE_W3C, employeeMandate(MACHINE_MANDATEE, mandatorWith("\"serialNumber\": null")),
                        SERIAL_NUMBER, ORGANIZATION_IDENTIFIER),
                Arguments.of(MACHINE_W3C, employeeMandate("{ \"domain\": \"machine.example.com\", \"ipAddress\": \"\" }", mandatorWith("\"email\": \"org@example.com\"")),
                        "/mandatee/ipAddress", "/mandatee/domain"),
                Arguments.of(EMPLOYEE_W3C, employeeMandate(
                        "{ \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"email\": \"jane.doe@example.com\", \"employeeId\": null }",
                        mandatorWith("\"email\": \"org@example.com\"")),
                        "/mandatee/employeeId", "/mandatee/firstName"),
                Arguments.of(EMPLOYEE_W3C, employeeMandate(
                        "{ \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"email\": \"jane.doe@example.com\", \"employeeId\": \"\" }",
                        mandatorWith("\"email\": \"org@example.com\"")),
                        "/mandatee/employeeId", "/mandatee/firstName"),
                Arguments.of(EMPLOYEE_W3C, mandate(EMPLOYEE_MANDATEE, mandatorWith("\"email\": \"org@example.com\""),
                        "[{ \"function\": \"Onboarding\", \"domain\": \"\" }]"),
                        "/power/0/domain", "/power/0/function"),
                Arguments.of(PID, "{ " + PID_BASE + ", \"document_number\": null }",
                        "/document_number", "/given_name")
        );
    }

    static Stream<Arguments> keptValues() {
        return Stream.of(
                Arguments.of(EMPLOYEE_W3C, employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": \"A15456585\"")),
                        SERIAL_NUMBER, "\"A15456585\""),
                Arguments.of(EMPLOYEE_W3C, employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": \" \"")),
                        SERIAL_NUMBER, "\" \""),
                Arguments.of(EMPLOYEE_W3C, employeeMandate(EMPLOYEE_MANDATEE,
                        "{ \"organizationIdentifier\": \"\", \"country\": \"ES\" }"),
                        ORGANIZATION_IDENTIFIER, "\"\""),
                Arguments.of(EMPLOYEE_SD, employeeMandate(
                        "{ \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"email\": \"jane.doe@example.com\", \"nationality\": null }",
                        mandatorWith("\"email\": \"org@example.com\"")),
                        "/mandatee/nationality", "null"),
                Arguments.of(PID, "{ " + PID_BASE + ", \"document_number\": \"12345678A\" }",
                        "/document_number", "\"12345678A\"")
        );
    }

    @Nested
    @DisplayName("normalize: optional string properties declared by the profile")
    class OptionalStrings {

        @ParameterizedTest(name = "normalize_{0}_{2}IsNullOrEmpty_removesItAndKeepsTheRest")
        @MethodSource("es.in2.issuer.backend.shared.infrastructure.service.IssuancePayloadNormalizerImplTest#removedOptionalValues")
        void normalize_optionalStringIsNullOrEmpty_removesItAndKeepsTheRest(
                String configId, String payloadJson, String removedPointer, String keptPointer) throws Exception {
            // Arrange
            JsonNode payload = json(payloadJson);

            // Act
            JsonNode result = normalizer.normalize(configId, payload);

            // Assert
            assertTrue(result.at(removedPointer).isMissingNode());
            assertFalse(result.at(keptPointer).isMissingNode());
        }

        @ParameterizedTest(name = "normalize_{0}_{2}_isNotRemoved")
        @MethodSource("es.in2.issuer.backend.shared.infrastructure.service.IssuancePayloadNormalizerImplTest#keptValues")
        void normalize_valueThatIsNotAnEmptyOptionalString_isNotRemoved(
                String configId, String payloadJson, String pointer, String expectedJson) throws Exception {
            // Arrange
            JsonNode payload = json(payloadJson);

            // Act
            JsonNode result = normalizer.normalize(configId, payload);

            // Assert
            assertEquals(json(expectedJson), result.at(pointer));
        }

        @Test
        void normalize_serialNumberAbsent_doesNotAddIt() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"email\": \"org@example.com\"")));

            // Act
            JsonNode result = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertTrue(result.at(SERIAL_NUMBER).isMissingNode());
        }

        @Test
        void normalize_emptyPowerEntry_keepsTheElementInTheArray() throws Exception {
            // Arrange
            JsonNode payload = json(mandate(EMPLOYEE_MANDATEE, mandatorWith("\"email\": \"org@example.com\""),
                    "[{ \"domain\": \"\" }]"));

            // Act
            JsonNode result = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertEquals(1, result.at("/power").size());
            assertTrue(result.at("/power/0").isObject());
        }
    }

    @Nested
    @DisplayName("normalize: required string properties")
    class RequiredStrings {

        @Test
        void normalize_requiredStringIsNull_removesItWithoutWritingAnEmptyString() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE,
                    "{ \"organizationIdentifier\": null, \"country\": \"ES\" }"));

            // Act
            JsonNode result = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertTrue(result.at(ORGANIZATION_IDENTIFIER).isMissingNode());
        }

        @Test
        void normalize_requiredStringIsNullThenValidated_failsOnTheRequiredProperty() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE,
                    "{ \"organizationIdentifier\": null, \"country\": \"ES\" }"));
            JsonNode normalized = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Act
            var result = validator.validate(EMPLOYEE_W3C, normalized);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> {
                        assertTrue(error instanceof PayloadValidationException);
                        var violations = ((PayloadValidationException) error).getViolations();
                        assertTrue(violations.stream().anyMatch(v -> v.message().contains("organizationIdentifier")));
                    })
                    .verify();
        }
    }

    @Nested
    @DisplayName("normalize: contract with the validator")
    class WithTheValidator {

        @Test
        void validate_serialNumberNullWithoutNormalizing_rejectsThePayload() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": null")));

            // Act
            var result = validator.validate(EMPLOYEE_W3C, payload);

            // Assert
            StepVerifier.create(result).expectError(PayloadValidationException.class).verify();
        }

        @Test
        void validate_serialNumberNullAfterNormalizing_completesSuccessfully() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": null")));
            JsonNode normalized = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Act
            var result = validator.validate(EMPLOYEE_W3C, normalized);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        void validate_employeeIdNullWithoutNormalizing_stillCompletesSuccessfully() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(
                    "{ \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"email\": \"jane.doe@example.com\", \"employeeId\": null }",
                    mandatorWith("\"email\": \"org@example.com\"")));

            // Act
            var result = validator.validate(EMPLOYEE_W3C, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }
    }

    @Nested
    @DisplayName("normalize: removal counter")
    class RemovalCounter {

        private static final String COUNTER = "issuance.payload.optional_string.removed";

        private double removed(String configId, String path, String reason) {
            var counter = meterRegistry.find(COUNTER)
                    .tag("credential_configuration_id", configId)
                    .tag("path", path)
                    .tag("reason", reason)
                    .counter();
            return counter == null ? 0 : counter.count();
        }

        @Test
        void normalize_serialNumberNull_countsTheRemovalWithPathAndReason() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": null")));

            // Act
            normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertEquals(1, removed(EMPLOYEE_W3C, "$.mandator.serialNumber", "null"));
        }

        @Test
        void normalize_serialNumberEmpty_countsTheRemovalAsEmpty() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": \"\"")));

            // Act
            normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertEquals(1, removed(EMPLOYEE_W3C, "$.mandator.serialNumber", "empty"));
        }

        @Test
        void normalize_emptyValuesInDifferentArrayPositions_shareOneCounterPath() throws Exception {
            // Arrange
            JsonNode payload = json(mandate(EMPLOYEE_MANDATEE, mandatorWith("\"email\": \"org@example.com\""),
                    "[{ \"domain\": \"\" }, { \"domain\": \"\" }]"));

            // Act
            normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertEquals(2, removed(EMPLOYEE_W3C, "$.power[].domain", "empty"));
        }

        @Test
        void normalize_nothingToRemove_doesNotCount() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": \"A15456585\"")));

            // Act
            normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertTrue(meterRegistry.find(COUNTER).counters().isEmpty());
        }

        @Test
        void normalize_requiredEmptyStringIsKept_doesNotCount() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE,
                    "{ \"organizationIdentifier\": \"\", \"country\": \"ES\" }"));

            // Act
            normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertTrue(meterRegistry.find(COUNTER).counters().isEmpty());
        }
    }

    @Nested
    @DisplayName("normalize: input handling")
    class InputHandling {

        @Test
        void normalize_payloadWithoutEmptyValues_returnsEqualContentInANewNode() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": \"A15456585\"")));

            // Act
            JsonNode result = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertEquals(payload, result);
            assertNotSame(payload, result);
        }

        @Test
        void normalize_payloadWithEmptyValues_doesNotModifyTheReceivedNode() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": null")));
            JsonNode snapshot = payload.deepCopy();

            // Act
            normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertEquals(snapshot, payload);
        }

        @Test
        void normalize_unknownConfigurationId_returnsThePayloadUntouched() throws Exception {
            // Arrange
            JsonNode payload = json(employeeMandate(EMPLOYEE_MANDATEE, mandatorWith("\"serialNumber\": null")));

            // Act
            JsonNode result = normalizer.normalize("unknown.config.1", payload);

            // Assert
            assertSame(payload, result);
        }

        @Test
        void normalize_payloadIsNotAnObject_returnsItUntouched() throws Exception {
            // Arrange
            JsonNode payload = json("[]");

            // Act
            JsonNode result = normalizer.normalize(EMPLOYEE_W3C, payload);

            // Assert
            assertSame(payload, result);
        }
    }
}
