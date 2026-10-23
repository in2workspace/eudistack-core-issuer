package es.in2.issuer.backend.shared.domain.model.catalog;

import java.util.Arrays;

/**
 * The entity tag of a catalog entry: its version as a strong ETag ({@code "3"}). {@code If-Match} may list
 * several tags (RFC 9110 section 13.1.1) and matches when any of them does, with the strong comparison of
 * section 8.8.3.2, so a weak tag ({@code W/"3"}) never matches.
 */
public final class CatalogEntryETag {

    private CatalogEntryETag() {
    }

    public static String of(CatalogEntry entry) {
        return of(entry.version());
    }

    public static String of(long version) {
        return "\"" + version + "\"";
    }

    /** {@code true} if one of the tags listed in {@code ifMatch} is exactly the strong tag of {@code version}. */
    public static boolean matches(String ifMatch, long version) {
        String current = of(version);
        // The tags are versions, so none holds a comma of its own to split on.
        return Arrays.stream(ifMatch.split(",")).map(String::strip).anyMatch(current::equals);
    }
}
