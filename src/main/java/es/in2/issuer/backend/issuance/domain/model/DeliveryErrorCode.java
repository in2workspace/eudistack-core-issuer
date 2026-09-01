package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Closed set of codes for {@code delivery_results[].error} (EUD-168 F3/W1).
 *
 * <p>Before this, a failed mode carried {@code Throwable.getMessage()} verbatim: for the direct leg
 * that can be a {@code WebClientResponseException}'s method/URL from the signing provider or the
 * status list, or an R2DBC failure's table/column/schema names -- and the schema name <em>is</em> the
 * tenant. Before AD-11 that same failure propagated to a {@code problem+json} sanitized by
 * {@code ErrorResponseFactory}; the per-mode isolation skipped that sanitizer. A code carries no more
 * than what the caller already knows from the mode and the request -- the raw detail stays server-side
 * in the log line the failure site already emits.
 */
public enum DeliveryErrorCode {

    SIGNING_FAILED("signing_failed"),
    STATUS_LIST_UNAVAILABLE("status_list_unavailable"),
    PERSISTENCE_FAILED("persistence_failed"),
    WALLET_DELIVERY_TIMEOUT("wallet_delivery_timeout"),
    /** Anything that isn't one of the classified stages above -- still safe, never raw. */
    DELIVERY_FAILED("delivery_failed");

    private final String value;

    DeliveryErrorCode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
