package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Closed set of problem types of a failed delivery (EUD-254 FR-03, AC-03): what the caller learns of a
 * valid request whose delivery flow could not be completed.
 *
 * <p>A code, never {@code Throwable.getMessage()} (EUD-168 F3/W1): a failure of the signing provider or
 * the status list can carry a method and URL, and an R2DBC failure the table, column and schema names --
 * and the schema name <em>is</em> the tenant. The raw detail stays server-side, in the log.
 *
 * <p>{@link #retryable()} separates a dependency that is temporarily unavailable, worth retrying later
 * (503 with {@code Retry-After}), from a failure a retry would not fix (500).
 */
public enum DeliveryErrorCode {

    SIGNING_FAILED("signing_failed", true),
    STATUS_LIST_UNAVAILABLE("status_list_unavailable", true),
    WALLET_DELIVERY_TIMEOUT("wallet_delivery_timeout", true),
    PERSISTENCE_FAILED("persistence_failed", false),
    /** Anything that isn't one of the classified stages above -- still safe, never raw. */
    DELIVERY_FAILED("delivery_failed", false);

    private final String value;
    private final boolean retryable;

    DeliveryErrorCode(String value, boolean retryable) {
        this.value = value;
        this.retryable = retryable;
    }

    @JsonValue
    public String value() {
        return value;
    }

    /** Whether a dependency of the delivery was temporarily unavailable, so the same request may be retried. */
    public boolean retryable() {
        return retryable;
    }

    /** Short, stable human summary of the failure -- never the raw cause. */
    public String title() {
        return switch (this) {
            case SIGNING_FAILED -> "Signing failed";
            case STATUS_LIST_UNAVAILABLE -> "Status list unavailable";
            case PERSISTENCE_FAILED -> "Persistence failed";
            case WALLET_DELIVERY_TIMEOUT -> "Wallet delivery timeout";
            case DELIVERY_FAILED -> "Delivery failed";
        };
    }
}
