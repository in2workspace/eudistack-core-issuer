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
                          "additionalProperties": false,
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
    @DisplayName("validate: payload carries fields outside the mandate schema")
    class InvalidPayload {

        @Test
        @DisplayName("validate_mandateeHasUnregisteredField_rejectsWithPayloadValidationException")
        void validate_mandateeHasUnregisteredField_rejectsWithPayloadValidationException() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe", "nationality": "ES" },
                      "mandator": { "organizationIdentifier": "VATES-A00000000", "email": "org@example.com" },
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

        @Test
        @DisplayName("validate_mandatorUsesLegacyEmailAddressFieldName_rejectsWithPayloadValidationException")
        void validate_mandatorUsesLegacyEmailAddressFieldName_rejectsWithPayloadValidationException() throws Exception {
            // Arrange
            mockMandateSchema();
            JsonNode payload = payload("""
                    {
                      "mandatee": { "email": "jane.doe@example.com", "firstName": "Jane", "lastName": "Doe" },
                      "mandator": { "organizationIdentifier": "VATES-A00000000", "emailAddress": "org@example.com" },
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
