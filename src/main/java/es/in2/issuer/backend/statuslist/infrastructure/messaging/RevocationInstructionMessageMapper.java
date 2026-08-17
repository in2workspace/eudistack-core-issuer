package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * Maps the wire DTO to the domain command, validating required fields and format at the
 * border (ES-01) rather than relying on deserialization to fail loudly. {@code tenantId}
 * is intentionally passed through as-is (including {@code null}): resolving/validating the
 * effective tenant is {@code RevocationTenantBinding}'s job (AD-8), not this mapper's.
 */
@Component
public class RevocationInstructionMessageMapper {

    /**
     * @param amqpMessageIdProperty fallback source for {@code messageId} when the message
     *                              body does not declare one (EC-01): the broker-native
     *                              {@code message-id} property, or {@code null} if absent.
     */
    public RevocationInstruction toDomain(RevocationInstructionMessage message, String amqpMessageIdProperty, Instant receivedAt) {
        String messageId = resolveMessageId(message.messageId(), amqpMessageIdProperty);
        String issuanceId = requireValidIssuanceId(message.issuanceId());
        return new RevocationInstruction(messageId, message.tenantId(), issuanceId, message.reason(), receivedAt);
    }

    private String resolveMessageId(String bodyMessageId, String amqpMessageIdProperty) {
        if (bodyMessageId != null && !bodyMessageId.isBlank()) {
            return bodyMessageId;
        }
        if (amqpMessageIdProperty != null && !amqpMessageIdProperty.isBlank()) {
            return amqpMessageIdProperty;
        }
        throw new InvalidRevocationInstructionException(
                "Revocation instruction has no messageId (neither the message body nor the AMQP message-id property)");
    }

    private String requireValidIssuanceId(String issuanceId) {
        if (issuanceId == null || issuanceId.isBlank()) {
            throw new InvalidRevocationInstructionException("Revocation instruction is missing issuanceId");
        }
        try {
            UUID.fromString(issuanceId);
        } catch (IllegalArgumentException e) {
            throw new InvalidRevocationInstructionException("Revocation instruction issuanceId is not a valid UUID: " + issuanceId);
        }
        return issuanceId;
    }
}
