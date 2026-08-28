package es.in2.issuer.backend.shared.domain.exception;

import java.util.UUID;

/**
 * A write to {@code issuance} lost the optimistic-locking race introduced by the
 * {@code version} column (SD-04, EUD-225): another writer updated the same row between
 * this write's read and its {@code save()}. Unlike {@code updateIssuanceStatusToRevoked}
 * (which reconciles this exact case into a no-op when the winner already reached the same
 * terminal REVOKED state), the call site that threw this exception has no defined
 * reconciliation target for a concurrent conflict within EUD-225's scope — the conflict is
 * real and is surfaced clearly here instead of silently overwriting another writer's change
 * or letting a bare R2DBC exception surface with no context.
 */
public class ConcurrentIssuanceUpdateException extends RuntimeException {
    public ConcurrentIssuanceUpdateException(UUID issuanceId, String operation, Throwable cause) {
        super("Concurrent update conflict on issuance " + issuanceId + " during " + operation, cause);
    }
}
