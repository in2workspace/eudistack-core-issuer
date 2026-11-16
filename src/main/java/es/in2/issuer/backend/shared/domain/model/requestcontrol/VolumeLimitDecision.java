package es.in2.issuer.backend.shared.domain.model.requestcontrol;

/**
 * Whether a request fits in its volume limit (EUD-269).
 *
 * @param allowed           the request goes on
 * @param limit             requests allowed in the window for this requester
 * @param retryAfterSeconds when rejected, seconds until one more request fits ({@code Retry-After});
 *                          0 when allowed
 */
public record VolumeLimitDecision(boolean allowed, int limit, long retryAfterSeconds) {

    public static VolumeLimitDecision allowed(int limit) {
        return new VolumeLimitDecision(true, limit, 0);
    }

    public static VolumeLimitDecision rejected(int limit, long retryAfterSeconds) {
        return new VolumeLimitDecision(false, limit, retryAfterSeconds);
    }
}
