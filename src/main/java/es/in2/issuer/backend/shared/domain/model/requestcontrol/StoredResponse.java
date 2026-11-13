package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.util.Arrays;
import java.util.Objects;

/**
 * A successful response kept for an idempotency key (EUD-269): what is returned again, byte for byte,
 * to a retry with the same key and body.
 *
 * @param status      HTTP status (2xx)
 * @param contentType {@code Content-Type}, or {@code null}
 * @param location    {@code Location}, or {@code null}
 * @param body        the body; empty when there was none
 */
public record StoredResponse(int status, String contentType, String location, byte[] body) {

    public StoredResponse {
        if (status < 200 || status > 299) {
            throw new IllegalArgumentException("Only successful responses are kept");
        }
        body = body != null ? body.clone() : new byte[0];
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof StoredResponse(int thatStatus, String thatContentType, String thatLocation,
                                               byte[] thatBody)
                && status == thatStatus
                && Objects.equals(contentType, thatContentType)
                && Objects.equals(location, thatLocation)
                && Arrays.equals(body, thatBody);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(status, contentType, location) + Arrays.hashCode(body);
    }

    /** The body is left out: it may carry personal data or a signed credential. */
    @Override
    public String toString() {
        return "StoredResponse[status=" + status + ", contentType=" + contentType
                + ", location=" + location + ", bodyBytes=" + body.length + "]";
    }
}
