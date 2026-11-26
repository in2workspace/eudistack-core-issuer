package es.in2.issuer.backend.shared.domain.model.query;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The opaque cursor of the query API (EUD-255 AD-1): the position of the last process of a page and
 * a digest of the filters it was asked with, as JSON in base64url. It is not signed: the caller's
 * scope always goes in the query, so a forged cursor only moves the starting point inside what the
 * caller may already see. The digest makes a cursor of other filters a bad request.
 */
public record PageCursor(PagePosition position, String filterDigest) {

    /** A real cursor is about 120 characters; anything far longer is not one. */
    static final int MAX_ENCODED_LENGTH = 512;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String LAST_CHANGED = "t";
    private static final String ID = "id";
    private static final String FILTERS = "f";

    public PageCursor {
        Objects.requireNonNull(position, "position");
        Objects.requireNonNull(filterDigest, "filterDigest");
    }

    public String encode() {
        ObjectNode node = JSON.createObjectNode()
                .put(LAST_CHANGED, position.lastChangedAt().toString())
                .put(ID, position.issuanceId().toString())
                .put(FILTERS, filterDigest);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(node.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** The cursor a client sent back, or empty when it is not one this API gave out. */
    public static Optional<PageCursor> decode(String encoded) {
        if (encoded == null || encoded.isEmpty() || encoded.length() > MAX_ENCODED_LENGTH) {
            return Optional.empty();
        }
        try {
            JsonNode node = JSON.readTree(Base64.getUrlDecoder().decode(encoded));
            if (node == null || !node.isObject()
                    || !node.path(LAST_CHANGED).isTextual()
                    || !node.path(ID).isTextual()
                    || !node.path(FILTERS).isTextual()) {
                return Optional.empty();
            }
            PagePosition position = new PagePosition(
                    Instant.parse(node.get(LAST_CHANGED).asText()),
                    UUID.fromString(node.get(ID).asText()));
            return Optional.of(new PageCursor(position, node.get(FILTERS).asText()));
        } catch (Exception _) {
            // Base64, JSON, date and UUID failures all mean the same thing to the client.
            return Optional.empty();
        }
    }
}
