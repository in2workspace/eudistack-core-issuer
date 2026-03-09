package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialDetailsTest {

    ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testConstructorAndGetters() {
        // Arrange
        UUID uuid = UUID.randomUUID();
        String expectedCredentialStatus = "Valid";
        String expectedCredentialJson = "{\"key\": \"value\"}";
        JsonNode jsonNode = null;
        String email = "email";
        try {
            jsonNode = objectMapper.readTree(expectedCredentialJson);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Act
        String configId = "learcredential.employee.w3c.4";
        CredentialDetails credentialDetails = new CredentialDetails(uuid, configId, expectedCredentialStatus, jsonNode, email);

        // Assert
        assertEquals(uuid, credentialDetails.issuanceId());
        assertEquals(configId, credentialDetails.credentialConfigurationId());
        assertEquals(expectedCredentialStatus, credentialDetails.lifeCycleStatus());
        assertEquals(jsonNode, credentialDetails.credential());
        assertEquals(email, credentialDetails.email());
    }

    @Test
    void testSetters() throws JsonProcessingException {
        // Arrange
        UUID uuid = UUID.randomUUID();
        String newCredentialStatus = "Revoked";
        JsonNode jsonNode = objectMapper.readTree("{\"key\": \"value\"}");

        // Act
        String configId = "learcredential.employee.w3c.4";
        CredentialDetails credentialDetails = CredentialDetails.builder()
                .issuanceId(uuid)
                .credentialConfigurationId(configId)
                .lifeCycleStatus(newCredentialStatus)
                .credential(jsonNode)
                .build();

        // Assert
        assertEquals(uuid, credentialDetails.issuanceId());
        assertEquals(newCredentialStatus, credentialDetails.lifeCycleStatus());
        assertEquals(jsonNode, credentialDetails.credential());
    }

    @Test
    void lombokGeneratedMethodsTest() throws JsonProcessingException {
        // Arrange
        UUID uuid = UUID.randomUUID();
        String expectedCredentialStatus = "Valid";
        JsonNode jsonNode = objectMapper.readTree("{\"key\": \"value\"}");
        String email = "email";

        String configId = "learcredential.employee.w3c.4";
        CredentialDetails credentialDetails = new CredentialDetails(uuid, configId, expectedCredentialStatus, jsonNode, email);
        CredentialDetails credentialDetails2 = new CredentialDetails(uuid, configId, expectedCredentialStatus, jsonNode, email);

        // Assert
        assertEquals(credentialDetails, credentialDetails2);
        assertEquals(credentialDetails.hashCode(), credentialDetails2.hashCode());
    }
}
