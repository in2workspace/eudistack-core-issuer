package es.in2.issuer.backend.shared.domain.model.query;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** EUD-255 AD-1: the cursor round-trips, and anything that is not one of ours is recognised as such. */
class PageCursorTest {

    @Test
    void encodeThenDecode_givesTheSameCursor() {
        PageCursor cursor = new PageCursor(
                new PagePosition(Instant.parse("2026-10-01T09:12:44.123456Z"), UUID.randomUUID()), "digest");

        String encoded = cursor.encode();

        assertThat(encoded).matches("[A-Za-z0-9_-]+");
        assertThat(PageCursor.decode(encoded)).contains(cursor);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "not a cursor!",
            "bm90IGpzb24",                       // base64url of "not json"
            "eyJ0IjoiMjAyNi0xMC0wMSJ9",          // {"t":"2026-10-01"}: fields missing
    })
    void decode_rejectsWhatIsNotACursor(String encoded) {
        assertThat(PageCursor.decode(encoded)).isEmpty();
    }

    @Test
    void decode_rejectsABadDateOrId() {
        assertThat(PageCursor.decode(json("{\"t\":\"yesterday\",\"id\":\"" + UUID.randomUUID() + "\",\"f\":\"x\"}"))).isEmpty();
        assertThat(PageCursor.decode(json("{\"t\":\"2026-10-01T09:00:00Z\",\"id\":\"42\",\"f\":\"x\"}"))).isEmpty();
        assertThat(PageCursor.decode(json("{\"t\":1,\"id\":\"" + UUID.randomUUID() + "\",\"f\":\"x\"}"))).isEmpty();
    }

    @Test
    void decode_rejectsAnOversizedValue() {
        assertThat(PageCursor.decode("a".repeat(PageCursor.MAX_ENCODED_LENGTH + 1))).isEmpty();
    }

    @Test
    void decode_rejectsNull() {
        assertThat(PageCursor.decode(null)).isEmpty();
    }

    private static String json(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
