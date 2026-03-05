package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PreAuthorizedCodeResponseTest {

    @Test
    void testConstructorAndGetters() {
        String expectedPreAuthorizedCode = "pre-auth-code-123";
        TxCode expectedTxCode = new TxCode(4, "numeric", "description");
        String expectedPin = "1234";

        PreAuthorizedCodeResponse response = new PreAuthorizedCodeResponse(
                expectedPreAuthorizedCode,
                expectedTxCode,
                expectedPin
        );

        assertEquals(expectedPreAuthorizedCode, response.preAuthorizedCode());
        assertEquals(expectedTxCode, response.txCode());
        assertEquals(expectedPin, response.pin());
    }

    @Test
    void testBuilder() {
        String expectedPreAuthorizedCode = "pre-auth-code-456";
        TxCode expectedTxCode = new TxCode(5, "numeric", "newDescription");
        String expectedPin = "5678";

        PreAuthorizedCodeResponse response = PreAuthorizedCodeResponse.builder()
                .preAuthorizedCode(expectedPreAuthorizedCode)
                .txCode(expectedTxCode)
                .pin(expectedPin)
                .build();

        assertEquals(expectedPreAuthorizedCode, response.preAuthorizedCode());
        assertEquals(expectedTxCode, response.txCode());
        assertEquals(expectedPin, response.pin());
    }
}
