package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class NotificationRequestTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    // Regression test: OID4VCI 1.0 FINAL §11.1 names these fields notification_id/
    // event_description (snake_case) in the request body. Without an explicit @JsonProperty
    // mapping, Jackson only matched the literal Java field name (notificationId), so a
    // spec-conformant request deserialized notificationId as null - passing @NotBlank's
    // presence check trivially false and rejecting every conformant call with 400. Caught by
    // the OIDF conformance suite's oid4vci-1_0-issuer-happy-flow test
    // (OID4VCI-1FINAL-11.2 EnsureHttpStatusCodeIs2xx on the notification endpoint).
    @Test
    void deserializes_specConformantSnakeCaseFields() throws Exception {
        String json = """
                {"notification_id":"notif-123","event":"credential_accepted","event_description":"ok"}
                """;

        NotificationRequest request = objectMapper.readValue(json, NotificationRequest.class);

        assertEquals("notif-123", request.notificationId());
        assertEquals(NotificationEvent.CREDENTIAL_ACCEPTED, request.event());
        assertEquals("ok", request.eventDescription());
    }

    // @JsonAlias keeps accepting the previous (non-conformant) camelCase key too, so an
    // un-updated Wallet PWA build in the field doesn't suddenly start failing every
    // notification once the Issuer requires the spec-correct key.
    @Test
    void deserializes_legacyCamelCaseFields_viaJsonAlias() throws Exception {
        String json = """
                {"notificationId":"notif-456","event":"credential_failure","eventDescription":"failed"}
                """;

        NotificationRequest request = objectMapper.readValue(json, NotificationRequest.class);

        assertEquals("notif-456", request.notificationId());
        assertEquals(NotificationEvent.CREDENTIAL_FAILURE, request.event());
        assertEquals("failed", request.eventDescription());
    }

    @Test
    void deserializes_withoutOptionalEventDescription() throws Exception {
        String json = """
                {"notification_id":"notif-789","event":"credential_deleted"}
                """;

        NotificationRequest request = objectMapper.readValue(json, NotificationRequest.class);

        assertEquals("notif-789", request.notificationId());
        assertEquals(NotificationEvent.CREDENTIAL_DELETED, request.event());
        assertNull(request.eventDescription());
    }
}
