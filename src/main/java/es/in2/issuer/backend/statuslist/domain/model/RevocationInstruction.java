package es.in2.issuer.backend.statuslist.domain.model;

import java.time.Instant;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

/**
 * Domain command produced by the revocation-instruction inbound adapter (AMQP listener)
 * once the wire message has been mapped and validated at the border.
 * <p>
 * {@code tenantId} is nullable: the wire contract makes it conditionally mandatory
 * (AD-8) — it is required in the default multi-tenant mode, but a single-tenant
 * deployment may declare its own tenant via configuration and omit it in the message.
 * The effective tenant is resolved separately by the tenant binding policy
 * (RevocationTenantBinding); this record only carries what the message itself declared.
 * {@code reason} is optional (resolución PO 2026-08-14).
 */
public record RevocationInstruction(
        String messageId,
        String tenantId,
        String issuanceId,
        String reason,
        Instant receivedAt
) {

    public RevocationInstruction {
        requireNonNullParam(messageId, "messageId");
        requireNonNullParam(issuanceId, "issuanceId");
        requireNonNullParam(receivedAt, "receivedAt");
    }
}
