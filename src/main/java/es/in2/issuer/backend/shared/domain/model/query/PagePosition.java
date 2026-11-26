package es.in2.issuer.backend.shared.domain.model.query;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;

import java.time.Instant;
import java.util.Comparator;
import java.util.Objects;
import java.util.UUID;

/**
 * Where an issuance process sits in the query order (EUD-255 AD-1): its last change, then its id,
 * both newest first. A page goes on after the position of the last process of the previous one.
 */
public record PagePosition(Instant lastChangedAt, UUID issuanceId) {

    /**
     * The order of {@code ORDER BY last_changed_at DESC, issuance_id DESC}. Postgres compares a
     * {@code uuid} byte by byte, unsigned; {@link UUID#compareTo} compares signed halves and would
     * order some ids differently, so the merge of several tenants (AD-3) uses this one.
     */
    public static final Comparator<PagePosition> NEWEST_FIRST = (a, b) -> {
        int byLastChange = b.lastChangedAt.compareTo(a.lastChangedAt);
        return byLastChange == 0 ? compareUnsigned(b.issuanceId, a.issuanceId) : byLastChange;
    };

    public PagePosition {
        Objects.requireNonNull(lastChangedAt, "lastChangedAt");
        Objects.requireNonNull(issuanceId, "issuanceId");
    }

    public static PagePosition of(Issuance issuance) {
        return new PagePosition(issuance.getLastChangedAt(), issuance.getIssuanceId());
    }

    static int compareUnsigned(UUID x, UUID y) {
        int high = Long.compareUnsigned(x.getMostSignificantBits(), y.getMostSignificantBits());
        return high == 0 ? Long.compareUnsigned(x.getLeastSignificantBits(), y.getLeastSignificantBits()) : high;
    }
}
