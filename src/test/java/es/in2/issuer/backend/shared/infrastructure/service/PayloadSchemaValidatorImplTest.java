package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PayloadSchemaValidatorImplTest {

    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String JWT_VC_JSON = "jwt_vc_json";

    private static final String RAW_PROFILE_WITH_MANDATE_SCHEMA = """
            {
              "credential_configuration_id": "learcredential.employee.w3c.4",
              "credential_format": "jwt_vc_json",
              "properties": {
                "credentialSubject": {
                  "type": "object",
                  "properties": {
                    "mandate": {
                      "type": "object",
                      "required": ["mandatee", "mandator", "power"],
                      "properties": {
                        "mandatee": {
                          "type": "object",
                          "additionalProperties": false,
                          "properties": {
                            "id":         { "type": "string", "format": "uri" },
                            "employeeId": { "type": "string" },
                            "email":      { "type": "string" },
                            "firstName":  { "type": "string" },
                            "lastName":   { "type": "string" }
                          }
                        },
                        "mandator": {
                          "type": "object",
                          "required": ["organizationIdentifier"],
                          "additionalProperties": false,
                          "properties": {
                            "id":                     { "type": "string", "format": "uri" },
                            "commonName":             { "type": "string" },
                            "country":                { "type": "string" },
                            "email":                  { "type": "string" },
                            "organization":           { "type": "string" },
                            "organizationIdentifier": { "type": "string" },
                            "serialNumber":           { "type": "string" }
                          }
                        },
                        "power": {
                          "type": "array",
                          "items": { "type": "object" }
                        }
                      }
                    }
                  }
                }
              }
            }
            """;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private PayloadSchemaValidatorImpl payloadSchemaValidator;

    @BeforeEach
    void setUp() {
        payloadSchemaValidator = new PayloadSchemaValidatorImpl(credentialProfileRegistry);
    }

    private void mockMandateSchema() throws Exception {
        JsonNode rawProfile = objectMapper.readTree(RAW_PROFILE_WITH_MANDATE_SCHEMA);
        when(credentialProfileRegistry.getRawProfile(CONFIG_ID)).thenReturn(rawProfile);
        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID))
                .thenReturn(CredentialProfile.builder()
                        .credentialConfigurationId(CONFIG_ID)
                        .format(JWT_VC_JSON)
                        .build());
    }

    private JsonNode payload(String mandateJson) throws Exception {
        return objectMapper.readTree(mandateJson);
    }

    private static final String VALID_MANDATEE = """
            { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" }""";
    private static final String VALID_MANDATOR = """
            { "organizationIdentifier": "VATES-A00000000", "email": "org@example.com" }""";

    private static String mandatePayload(String mandatee, String mandator) {
        return "{ \"mandatee\": " + mandatee + ", \"mandator\": " + mandator + ", \"power\": [{ \"type\": \"domain\" }] }";
    }

    static Stream<Arguments> conformingPayloads() {
        return Stream.of(
                Arguments.of("onlyRegisteredFields",
                        mandatePayload(VALID_MANDATEE, VALID_MANDATOR)),
                Arguments.of("mandateeAndMandatorIncludeIdField",
                        mandatePayload(
                                """
                                { "id": "did:key:zMandatee", "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" }""",
                                """
                                { "id": "did:elsi:VATES-A00000000", "organizationIdentifier": "VATES-A00000000", "email": "org@example.com" }""")),
                Arguments.of("mandateeEmployeeIdIsEmptyString",
                        mandatePayload(
                                """
                                { "employeeId": "", "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" }""",
                                VALID_MANDATOR))
        );
    }

    static Stream<Arguments> nonConformingPayloads() {
        return Stream.of(
                Arguments.of("mandateeEmployeeIdIsNull", "employeeId",
                        mandatePayload(
                                """
                                { "employeeId": null, "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" }""",
                                VALID_MANDATOR)),
                Arguments.of("mandateeHasUnregisteredField", "mandatee",
                        mandatePayload(
                                """
                                { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe", "nationality": "ES" }""",
                                VALID_MANDATOR)),
                Arguments.of("mandatorUsesLegacyEmailAddressFieldName", "mandator",
                        mandatePayload(
                                VALID_MANDATEE,
                                """
                                { "organizationIdentifier": "VATES-A00000000", "emailAddress": "org@example.com" }"""))
        );
    }

    @Nested
    @DisplayName("validate: payload conforms to the mandate schema")
    class ValidPayload {

        @ParameterizedTest(name = "validate_{0}_completesSuccessfully")
        @MethodSource("es.in2.issuer.backend.shared.infrastructure.service.PayloadSchemaValidatorImplTest#conformingPayloads")
        void validate_conformingPayload_completesSuccessfully(String scenario, String payloadJson) throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload(payloadJson);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }
    }

    @Nested
    @DisplayName("validate: payload carries fields outside the mandate schema")
    class InvalidPayload {

        @ParameterizedTest(name = "validate_{0}_rejectsWithPayloadValidationException")
        @MethodSource("es.in2.issuer.backend.shared.infrastructure.service.PayloadSchemaValidatorImplTest#nonConformingPayloads")
        void validate_nonConformingPayload_rejectsWithPayloadValidationException(
                String scenario, String violatedField, String payloadJson) throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload(payloadJson);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> {
                        assertTrue(error instanceof PayloadValidationException);
                        var violations = ((PayloadValidationException) error).getViolations();
                        assertTrue(violations.stream()
                                .anyMatch(v -> v.field().contains(violatedField)));
                    })
                    .verify();
        }
    }

    @Nested
    @DisplayName("validate: no schema registered for the credential configuration")
    class MissingSchema {

        @Test
        @DisplayName("validate_noRawProfileRegisteredForConfigurationId_completesWithoutValidating")
        void validate_noRawProfileRegisteredForConfigurationId_completesWithoutValidating() throws Exception {
            // Arrange
            when(credentialProfileRegistry.getRawProfile(CONFIG_ID)).thenReturn(null);
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": "jane.doe@example.com", "nationality": "ES" },
                      "mandator": { "organizationIdentifier": "VATES-A00000000", "emailAddress": "org@example.com" },
                      "power": []
                    }
                    """);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }
    }
}
