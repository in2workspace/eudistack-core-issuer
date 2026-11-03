package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class IssuanceRequestWithPayloadTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void withPayload_requestWithEveryComponent_replacesOnlyThePayload() {
        // Arrange
        JsonNode originalPayload = objectMapper.createObjectNode().put("name", "original");
        JsonNode holderKey = objectMapper.createObjectNode().put("kid", "holder-key");
        JsonNode newPayload = objectMapper.createObjectNode().put("name", "replacement");
        IssuanceRequest request = new IssuanceRequest(
                "learcredential.employee.w3c.4", originalPayload, "email", "jane.doe@example.com",
                "authorization_code", holderKey);

        // Act
        IssuanceRequest result = request.withPayload(newPayload);

        // Assert
        assertSame(newPayload, result.payload());
        assertEquals(request.credentialConfigurationId(), result.credentialConfigurationId());
        assertEquals(request.delivery(), result.delivery());
        assertEquals(request.email(), result.email());
        assertEquals(request.grantType(), result.grantType());
        assertSame(holderKey, result.holderKey());
    }

    @Test
    void withPayload_anyRequest_doesNotModifyTheOriginalRequest() {
        // Arrange
        JsonNode originalPayload = objectMapper.createObjectNode().put("name", "original");
        IssuanceRequest request = new IssuanceRequest(
                "learcredential.employee.w3c.4", originalPayload, "email", "jane.doe@example.com", null);

        // Act
        IssuanceRequest result = request.withPayload(objectMapper.createObjectNode());

        // Assert
        assertNotSame(request, result);
        assertSame(originalPayload, request.payload());
    }
}
