package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.util.Arrays;
import java.util.Objects;

/**
 * What happens to a request with an idempotency key (EUD-269, FR-08 of EUD-254).
 */
public sealed interface IdempotencyClaim {

    /**
     * The request holds the key and is processed; its owner completes or releases it.
     *
     * @param scopeKey    the stored key (a digest of the requester and the idempotency key)
     * @param ownerId     the request that holds it
     * @param responseKey key that encrypts the response to keep, derived from the idempotency key, which is
     *                    never stored; {@code null} until the service derives it
     */
    record Acquired(String scopeKey, String ownerId, byte[] responseKey) implements IdempotencyClaim {

        public Acquired(String scopeKey, String ownerId) {
            this(scopeKey, ownerId, null);
        }

        public Acquired {
            responseKey = responseKey != null ? responseKey.clone() : null;
        }

        @Override
        public byte[] responseKey() {
            return responseKey != null ? responseKey.clone() : null;
        }

        public Acquired withResponseKey(byte[] key) {
            return new Acquired(scopeKey, ownerId, key);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Acquired that
                    && Objects.equals(scopeKey, that.scopeKey)
                    && Objects.equals(ownerId, that.ownerId)
                    && Arrays.equals(responseKey, that.responseKey);
        }

        @Override
        public int hashCode() {
            return 31 * Objects.hash(scopeKey, ownerId) + Arrays.hashCode(responseKey);
        }

        /** The response key is never printed. */
        @Override
        public String toString() {
            return "Acquired[scopeKey=" + scopeKey + ", ownerId=" + ownerId + ", responseKey=redacted]";
        }
    }

    /** The key already has a successful response for the same body: it is returned again. */
    record Replay(StoredResponse response) implements IdempotencyClaim { }

    /** Another request with the same key and body is in progress (409 {@code idempotency_in_progress}). */
    record InProgress() implements IdempotencyClaim { }

    /** The key was used with another body (422 {@code idempotency_key_reused}). */
    record KeyReused() implements IdempotencyClaim { }
}
