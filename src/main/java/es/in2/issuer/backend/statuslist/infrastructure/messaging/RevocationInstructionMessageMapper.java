package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Maps the wire DTO to the domain command, validating required fields and format at the
 * border (ES-01) rather than relying on deserialization to fail loudly. {@code tenantId}
 * is intentionally passed through as-is (including {@code null}): resolving/validating the
 * effective tenant is {@code RevocationTenantBinding}'s job (AD-8), not this mapper's.
 */
@Component
public class RevocationInstructionMessageMapper {

    // technical-design.md §3.3.1: messageId has a bounded max length (idempotency key,
    // revocation_instruction_inbox.message_id TEXT PRIMARY KEY). An unbounded value both
    // risks an unclassified Postgres btree-index-limit exception on INSERT -- which
    // RevocationInstructionErrorClassifier would otherwise treat as retryable instead of
    // permanent (F3, EUD-225 /verify) -- and is exactly the kind of third-party content F1
    // sanitizes before logging. Rejected here, not silently truncated/stripped: normalizing
    // the idempotency key itself risks two distinct raw messageIds silently colliding.
    private static final int MAX_MESSAGE_ID_LENGTH = 200;
    private static final Pattern MESSAGE_ID_FORBIDDEN_CHARS = Pattern.compile("\\p{Cntrl}");

    /**
     * @param amqpMessageIdProperty fallback source for {@code messageId} when the message
     *                              body does not declare one (EC-01): the broker-native
     *                              {@code message-id} property, or {@code null} if absent.
     */
    public RevocationInstruction toDomain(RevocationInstructionMessage message, String amqpMessageIdProperty, Instant receivedAt) {
        String messageId = requireValidMessageId(resolveMessageId(message.messageId(), amqpMessageIdProperty));
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

    private String requireValidMessageId(String messageId) {
        if (messageId.length() > MAX_MESSAGE_ID_LENGTH) {
            throw new InvalidRevocationInstructionException(
                    "Revocation instruction messageId exceeds the maximum length of "
                            + MAX_MESSAGE_ID_LENGTH + " characters");
        }
        if (MESSAGE_ID_FORBIDDEN_CHARS.matcher(messageId).find()) {
            throw new InvalidRevocationInstructionException(
                    "Revocation instruction messageId contains forbidden control characters");
        }
        return messageId;
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
