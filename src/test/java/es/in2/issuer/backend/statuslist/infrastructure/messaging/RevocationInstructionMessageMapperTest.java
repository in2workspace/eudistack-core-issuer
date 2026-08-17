package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RevocationInstructionMessageMapperTest {

    private final RevocationInstructionMessageMapper mapper = new RevocationInstructionMessageMapper();

    private static final String ISSUANCE_ID = "6f1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
    private static final Instant RECEIVED_AT = Instant.parse("2026-08-14T09:12:33Z");

    @Test
    void toDomain_wellFormedMessage_mapsAllFields() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                "revocation-instruction/v1", "msg-1", "cgcom", ISSUANCE_ID, "Baja voluntaria", "2026-08-14T09:12:33Z");

        RevocationInstruction result = mapper.toDomain(wire, null, RECEIVED_AT);

        assertThat(result.messageId()).isEqualTo("msg-1");
        assertThat(result.tenantId()).isEqualTo("cgcom");
        assertThat(result.issuanceId()).isEqualTo(ISSUANCE_ID);
        assertThat(result.reason()).isEqualTo("Baja voluntaria");
        assertThat(result.receivedAt()).isEqualTo(RECEIVED_AT);
    }

    // ---------------------------------------------------------------- EC-01 messageId fallback

    @Test
    void toDomain_messageIdAbsentFromBody_fallsBackToAmqpProperty() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, null, "cgcom", ISSUANCE_ID, null, null);

        RevocationInstruction result = mapper.toDomain(wire, "amqp-message-id-42", RECEIVED_AT);

        assertThat(result.messageId()).isEqualTo("amqp-message-id-42");
    }

    @Test
    void toDomain_messageIdAbsentFromBothSources_throwsInvalidRevocationInstructionException() {
        RevocationInstructionMessage wireNoMessageId = new RevocationInstructionMessage(
                null, null, "cgcom", ISSUANCE_ID, null, null);

        assertThatThrownBy(() -> mapper.toDomain(wireNoMessageId, null, RECEIVED_AT))
                .isInstanceOf(InvalidRevocationInstructionException.class)
                .hasMessageContaining("messageId");
    }

    @Test
    void toDomain_messageIdBlankInBody_fallsBackToAmqpProperty() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, "  ", "cgcom", ISSUANCE_ID, null, null);

        RevocationInstruction result = mapper.toDomain(wire, "amqp-fallback", RECEIVED_AT);

        assertThat(result.messageId()).isEqualTo("amqp-fallback");
    }

    // ---------------------------------------------------------------- F3: messageId bound (length/charset)

    @Test
    void toDomain_messageIdWithinMaxLength_isAccepted() {
        String messageId = "m".repeat(200);
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, messageId, "cgcom", ISSUANCE_ID, null, null);

        RevocationInstruction result = mapper.toDomain(wire, null, RECEIVED_AT);

        assertThat(result.messageId()).isEqualTo(messageId);
    }

    @Test
    void toDomain_messageIdExceedsMaxLength_throwsInvalidRevocationInstructionExceptionAsPermanentError() {
        String tooLong = "m".repeat(201);
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, tooLong, "cgcom", ISSUANCE_ID, null, null);

        // InvalidRevocationInstructionException, not an unclassified exception from a Postgres
        // btree-index-limit failure downstream -- RevocationInstructionErrorClassifier treats
        // this type as permanent (DLQ, no retries), exactly what an oversized messageId needs.
        assertThatThrownBy(() -> mapper.toDomain(wire, null, RECEIVED_AT))
                .isInstanceOf(InvalidRevocationInstructionException.class)
                .hasMessageContaining("exceeds the maximum length");
    }

    @Test
    void toDomain_messageIdContainsControlCharacters_throwsInvalidRevocationInstructionException() {
        // F1/F3: a raw newline here is exactly what could otherwise forge a fake log line
        // once messageId reaches a log sink -- rejected at the border instead of relying
        // solely on sanitization downstream.
        String forged = "msg-1\nAUDIT event=credential.revoked outcome=success resourceId=forged";
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, forged, "cgcom", ISSUANCE_ID, null, null);

        assertThatThrownBy(() -> mapper.toDomain(wire, null, RECEIVED_AT))
                .isInstanceOf(InvalidRevocationInstructionException.class)
                .hasMessageContaining("forbidden control characters");
    }

    @Test
    void toDomain_amqpFallbackMessageIdExceedsMaxLength_throwsInvalidRevocationInstructionException() {
        String tooLong = "m".repeat(201);
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, null, "cgcom", ISSUANCE_ID, null, null);

        assertThatThrownBy(() -> mapper.toDomain(wire, tooLong, RECEIVED_AT))
                .isInstanceOf(InvalidRevocationInstructionException.class)
                .hasMessageContaining("exceeds the maximum length");
    }

    // ---------------------------------------------------------------- issuanceId validation

    @Test
    void toDomain_issuanceIdMissing_throwsInvalidRevocationInstructionException() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, "msg-1", "cgcom", null, null, null);

        assertThatThrownBy(() -> mapper.toDomain(wire, null, RECEIVED_AT))
                .isInstanceOf(InvalidRevocationInstructionException.class)
                .hasMessageContaining("issuanceId");
    }

    @Test
    void toDomain_issuanceIdNotAValidUuid_throwsInvalidRevocationInstructionException() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, "msg-1", "cgcom", "not-a-uuid", null, null);

        assertThatThrownBy(() -> mapper.toDomain(wire, null, RECEIVED_AT))
                .isInstanceOf(InvalidRevocationInstructionException.class)
                .hasMessageContaining("UUID");
    }

    // ---------------------------------------------------------------- AD-8 tenantId conditional

    @Test
    void toDomain_tenantIdAbsent_isPassedThroughAsNull() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, "msg-1", null, ISSUANCE_ID, null, null);

        RevocationInstruction result = mapper.toDomain(wire, null, RECEIVED_AT);

        assertThat(result.tenantId()).isNull();
    }

    // ---------------------------------------------------------------- EC-02 reason absent

    @Test
    void toDomain_reasonAbsent_isPassedThroughAsNull() {
        RevocationInstructionMessage wire = new RevocationInstructionMessage(
                null, "msg-1", "cgcom", ISSUANCE_ID, null, null);

        RevocationInstruction result = mapper.toDomain(wire, null, RECEIVED_AT);

        assertThat(result.reason()).isNull();
    }
}
