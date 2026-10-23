package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

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
                          "additionalProperties": true,
                          "properties": {
                            "id":         { "type": "string", "format": "uri" },
                            "employeeId": { "type": ["string", "null"] },
                            "email":      { "type": "string" },
                            "firstName":  { "type": "string" },
                            "lastName":   { "type": "string" }
                          }
                        },
                        "mandator": {
                          "type": "object",
                          "required": ["organizationIdentifier"],
                          "additionalProperties": true,
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
        payloadSchemaValidator = new PayloadSchemaValidatorImpl(new PayloadSubschemaResolver(credentialProfileRegistry));
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

    @Nested
    @DisplayName("validate: payload conforms to the mandate schema")
    class ValidPayload {

        @Test
        @DisplayName("validate_payloadUsesOnlyRegisteredFields_completesSuccessfully")
        void validate_payloadUsesOnlyRegisteredFields_completesSuccessfully() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" },
                      "mandator": { "organizationIdentifier": "VATES-A00000000", "email": "org@example.com" },
                      "power": [{ "type": "domain" }]
                    }
                    """);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        @DisplayName("validate_mandateeAndMandatorIncludeIdField_completesSuccessfully")
        void validate_mandateeAndMandatorIncludeIdField_completesSuccessfully() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "id": "did:key:zMandatee", "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" },
                      "mandator": { "id": "did:elsi:VATES-A00000000", "organizationIdentifier": "VATES-A00000000", "email": "org@example.com" },
                      "power": [{ "type": "domain" }]
                    }
                    """);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }
    }

    @Nested
    @DisplayName("validate: payload carries additional business attributes")
    class AdditionalAttributes {

        @Test
        @DisplayName("validate_mandateeHasUndeclaredAttribute_completesSuccessfully")
        void validate_mandateeHasUndeclaredAttribute_completesSuccessfully() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe", "externalReference": "REF-1" },
                      "mandator": { "organizationIdentifier": "VATES-A00000000", "email": "org@example.com" },
                      "power": [{ "type": "domain" }]
                    }
                    """);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }
    }

    @Nested
    @DisplayName("validate: payload breaks the mandate schema")
    class InvalidPayload {

        @Test
        @DisplayName("validate_mandatorMissesRequiredOrganizationIdentifier_rejectsWithPayloadValidationException")
        void validate_mandatorMissesRequiredOrganizationIdentifier_rejectsWithPayloadValidationException() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" },
                      "mandator": { "email": "org@example.com" },
                      "power": [{ "type": "domain" }]
                    }
                    """);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> {
                        assertTrue(error instanceof PayloadValidationException);
                        var violations = ((PayloadValidationException) error).getViolations();
                        assertTrue(violations.stream()
                                .anyMatch(v -> v.field().contains("mandator")));
                    })
                    .verify();
        }

        @Test
        @DisplayName("validate_mandateeEmailHasWrongDataType_rejectsWithPayloadValidationException")
        void validate_mandateeEmailHasWrongDataType_rejectsWithPayloadValidationException() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": 42, "firstName": "Jane", "lastName": "Doe" },
                      "mandator": { "organizationIdentifier": "VATES-A00000000" },
                      "power": [{ "type": "domain" }]
                    }
                    """);

            // Act
            var result = payloadSchemaValidator.validate(CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> {
                        assertTrue(error instanceof PayloadValidationException);
                        var violations = ((PayloadValidationException) error).getViolations();
                        assertTrue(violations.stream()
                                .anyMatch(v -> v.field().contains("mandatee")));
                    })
                    .verify();
        }
    }

    @Nested
    @DisplayName("validate: SD-JWT profile with claims at the root")
    class SdJwtDirectProfile {

        private static final String SD_CONFIG_ID = "doctorid.sd.1";

        private static final String RAW_DOCTOR_PROFILE = """
                {
                  "credential_configuration_id": "doctorid.sd.1",
                  "type": "object",
                  "required": ["givenName", "familyName", "personal_administrative_number", "medical_speciality"],
                  "additionalProperties": true,
                  "properties": {
                    "givenName": { "type": "string" },
                    "familyName": { "type": "string" },
                    "personal_administrative_number": { "type": "string", "pattern": "^[0-9]{9}$" },
                    "medical_speciality": { "type": "array", "items": { "type": "string" } },
                    "legally_entitled": { "type": "boolean" }
                  }
                }
                """;

        private static final String VALID_DOCTOR = """
                {
                  "givenName": "Jane",
                  "familyName": "Doe",
                  "personal_administrative_number": "282801234",
                  "medical_speciality": ["Cardiology"]
                }
                """;

        private void mockDoctorSchema() throws Exception {
            when(credentialProfileRegistry.getRawProfile(SD_CONFIG_ID))
                    .thenReturn(objectMapper.readTree(RAW_DOCTOR_PROFILE));
            when(credentialProfileRegistry.getByConfigurationId(SD_CONFIG_ID))
                    .thenReturn(CredentialProfile.builder()
                            .credentialConfigurationId(SD_CONFIG_ID)
                            .format("dc+sd-jwt")
                            .credentialSubjectStrategy("direct")
                            .build());
        }

        @Test
        @DisplayName("validate_allMandatoryClaimsPresent_completesSuccessfully")
        void validate_allMandatoryClaimsPresent_completesSuccessfully() throws Exception {
            // Arrange
            mockDoctorSchema();
            JsonNode payload = payload(VALID_DOCTOR);

            // Act
            var result = payloadSchemaValidator.validate(SD_CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        @DisplayName("validate_undeclaredBusinessClaim_completesSuccessfully")
        void validate_undeclaredBusinessClaim_completesSuccessfully() throws Exception {
            // Arrange
            mockDoctorSchema();
            ObjectNode payload = (ObjectNode) payload(VALID_DOCTOR);
            payload.put("externalReference", "REF-1");

            // Act
            var result = payloadSchemaValidator.validate(SD_CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        @DisplayName("validate_mandatoryClaimMissing_rejectsWithPayloadValidationException")
        void validate_mandatoryClaimMissing_rejectsWithPayloadValidationException() throws Exception {
            // Arrange
            mockDoctorSchema();
            ObjectNode payload = (ObjectNode) payload(VALID_DOCTOR);
            payload.remove("medical_speciality");

            // Act
            var result = payloadSchemaValidator.validate(SD_CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> {
                        assertTrue(error instanceof PayloadValidationException);
                        var violations = ((PayloadValidationException) error).getViolations();
                        assertTrue(violations.stream()
                                .anyMatch(v -> v.message().contains("medical_speciality")));
                    })
                    .verify();
        }

        @Test
        @DisplayName("validate_declaredClaimHasWrongDataType_rejectsWithPayloadValidationException")
        void validate_declaredClaimHasWrongDataType_rejectsWithPayloadValidationException() throws Exception {
            // Arrange
            mockDoctorSchema();
            ObjectNode payload = (ObjectNode) payload(VALID_DOCTOR);
            payload.put("legally_entitled", "yes");

            // Act
            var result = payloadSchemaValidator.validate(SD_CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result)
                    .expectError(PayloadValidationException.class)
                    .verify();
        }

        @ParameterizedTest
        @ValueSource(strings = {"iss", "sub", "aud", "jti", "iat", "nbf", "exp", "vct", "cnf", "status",
                "_sd", "_sd_alg", "validFrom", "validUntil"})
        @DisplayName("validate_additionalClaimUsesReservedName_rejectsWithPayloadValidationException")
        void validate_additionalClaimUsesReservedName_rejectsWithPayloadValidationException(String reservedName) throws Exception {
            // Arrange
            mockDoctorSchema();
            ObjectNode payload = (ObjectNode) payload(VALID_DOCTOR);
            payload.put(reservedName, "forged");

            // Act
            var result = payloadSchemaValidator.validate(SD_CONFIG_ID, payload);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> {
                        assertTrue(error instanceof PayloadValidationException);
                        var violations = ((PayloadValidationException) error).getViolations();
                        assertTrue(violations.stream()
                                .anyMatch(v -> v.field().equals("$." + reservedName)));
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
