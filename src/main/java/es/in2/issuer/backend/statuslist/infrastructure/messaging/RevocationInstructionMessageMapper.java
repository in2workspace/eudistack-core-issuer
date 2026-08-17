package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.statuslist.application.RevocationAuditDetails;
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
 * is intentionally passed through as-is when absent (including {@code null}): resolving
 * the effective tenant is {@code RevocationTenantBinding}'s job (AD-8), not this mapper's
 * — but when present, its charset/length are validated here regardless of what the
 * resolution outcome ends up being (F14, EUD-225 {@code /verify}): the {@code Mismatch}
 * path in particular never re-validates {@code declaredInMessage()} format, so a malformed
 * tenantId must be rejected before it can reach that far.
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

    // F14 (EUD-225 /verify): same criterion as TenantDomainWebFilter's tenant name pattern
    // (also RevocationAuditDetails.declaredTenantAuditFields, F15) -- a legitimate tenant
    // identifier already has to satisfy this, so rejecting anything else at the border
    // closes the gap on every resolution outcome, including Mismatch, which never
    // re-validates declaredInMessage() format on its own.
    private static final int MAX_TENANT_ID_LENGTH = 64;
    private static final Pattern TENANT_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    // reason is genuinely freeform human text (unlike messageId/tenantId, which are
    // identifiers) -- bounded here only against an oversized payload; control characters
    // are stripped (not rejected) further downstream by RevocationAuditDetails.sanitizeReason,
    // shared with the operator-triggered revocation path.
    private static final int MAX_REASON_LENGTH = 1_000;

    /**
     * @param amqpMessageIdProperty fallback source for {@code messageId} when the message
     *                              body does not declare one (EC-01): the broker-native
     *                              {@code message-id} property, or {@code null} if absent.
     */
    public RevocationInstruction toDomain(RevocationInstructionMessage message, String amqpMessageIdProperty, Instant receivedAt) {
        String messageId = requireValidMessageId(resolveMessageId(message.messageId(), amqpMessageIdProperty));
        String tenantId = requireValidTenantIdIfPresent(message.tenantId());
        String issuanceId = requireValidIssuanceId(message.issuanceId());
        String reason = requireValidReasonIfPresent(message.reason());
        return new RevocationInstruction(messageId, tenantId, issuanceId, reason, receivedAt);
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
        if (RevocationAuditDetails.FORBIDDEN_LOG_CHARS.matcher(messageId).find()) {
            throw new InvalidRevocationInstructionException(
                    "Revocation instruction messageId contains forbidden control characters");
        }
        return messageId;
    }

    /** {@code tenantId} stays conditionally optional (AD-8) -- {@code null}/blank passes
     *  through untouched. When present, its charset/length are enforced here regardless of
     *  what {@code RevocationTenantBinding.resolve} later does with it (F14). */
    private String requireValidTenantIdIfPresent(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            return tenantId;
        }
        if (tenantId.length() > MAX_TENANT_ID_LENGTH) {
            throw new InvalidRevocationInstructionException(
                    "Revocation instruction tenantId exceeds the maximum length of "
                            + MAX_TENANT_ID_LENGTH + " characters");
        }
        if (!TENANT_ID_PATTERN.matcher(tenantId).matches()) {
            throw new InvalidRevocationInstructionException(
                    "Revocation instruction tenantId has an invalid format");
        }
        return tenantId;
    }

    private String requireValidReasonIfPresent(String reason) {
        if (reason == null) {
            return null;
        }
        if (reason.length() > MAX_REASON_LENGTH) {
            throw new InvalidRevocationInstructionException(
                    "Revocation instruction reason exceeds the maximum length of "
                            + MAX_REASON_LENGTH + " characters");
        }
        return reason;
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
