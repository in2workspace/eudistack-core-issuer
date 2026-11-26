package es.in2.issuer.backend.shared.domain.model.query;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** EUD-255 AD-1/AD-3: the Java order of positions is the order of the database. */
class PagePositionTest {

    private static final Instant T = Instant.parse("2026-10-01T09:00:00Z");

    @Test
    void newestLastChangeGoesFirst() {
        PagePosition older = new PagePosition(T, UUID.randomUUID());
        PagePosition newer = new PagePosition(T.plusSeconds(1), UUID.randomUUID());

        List<PagePosition> sorted = sorted(older, newer);

        assertThat(sorted).containsExactly(newer, older);
    }

    /**
     * A uuid whose first byte is 0x80 or more is negative for {@link UUID#compareTo} but greater for
     * Postgres, which compares bytes unsigned. The order must follow Postgres.
     */
    @Test
    void onATie_theIdIsComparedLikePostgres_unsigned() {
        PagePosition high = new PagePosition(T, UUID.fromString("ffffffff-0000-4000-8000-000000000000"));
        PagePosition low = new PagePosition(T, UUID.fromString("7fffffff-0000-4000-8000-000000000000"));
        assertThat(high.issuanceId()).isLessThan(low.issuanceId());

        List<PagePosition> sorted = sorted(low, high);

        assertThat(sorted).containsExactly(high, low);
    }

    @Test
    void theLowHalfIsUnsignedToo() {
        PagePosition high = new PagePosition(T, UUID.fromString("00000000-0000-4000-f000-000000000000"));
        PagePosition low = new PagePosition(T, UUID.fromString("00000000-0000-4000-7000-000000000000"));

        assertThat(sorted(low, high)).containsExactly(high, low);
    }

    private static List<PagePosition> sorted(PagePosition... positions) {
        List<PagePosition> list = new ArrayList<>(List.of(positions));
        list.sort(PagePosition.NEWEST_FIRST);
        return list;
    }
}
