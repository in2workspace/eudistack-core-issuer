package es.in2.issuer.backend.issuance.domain.model;

import java.util.Set;

/**
 * Audit trace of a credential delivery (EUD-170 / US-04): the delivery mode(s) applied,
 * their per-mode result and the tenant of the operation.
 *
 * <p>PII-safe by construction: there is no field, constructor argument or accessor through
 * which a recipient email, holder identifier or credential claim could reach this type.
 * {@code recipientPseudonym}, when present, MUST already be a salted hash (see
 * {@link es.in2.issuer.backend.shared.domain.util.RecipientPseudonymizer}), never the raw value.
 */
public record DeliveryTrace(
        Set<DeliveryResult> results,
        String tenantId,
        String processId,
        String recipientPseudonym
) {

    public static final String EVENT_NAME = "credential.delivered";

    public DeliveryTrace {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("DeliveryTrace requires a resolved tenantId; refusing to trace against a default tenant");
        }
        if (processId == null || processId.isBlank()) {
            throw new IllegalArgumentException("DeliveryTrace requires a processId for correlation");
        }
        if (results == null || results.isEmpty()) {
            throw new IllegalArgumentException("DeliveryTrace requires at least one DeliveryResult");
        }
        results = Set.copyOf(results);
    }

    /** Convenience factory without a recipient pseudonym (the default per AD-2 — data minimization). */
    public static DeliveryTrace of(String tenantId, String processId, Set<DeliveryResult> results) {
        return new DeliveryTrace(results, tenantId, processId, null);
    }

    /** {@code true} when at least one delivery mode did not complete (status {@code FAILED}). */
    public boolean hasFailure() {
        return results.stream().anyMatch(r -> r.status() == DeliveryResult.DeliveryOutcome.FAILED);
    }
}
