package es.in2.issuer.backend.shared.domain.model.catalog;

/**
 * The entity tag of a catalog entry: its version as a strong ETag ({@code "3"}). {@code If-Match} uses
 * the strong comparison of RFC 9110 section 8.8.3.2, so a weak tag ({@code W/"3"}) never matches.
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

    /** {@code true} if {@code ifMatch} is exactly the strong tag of {@code version}. */
    public static boolean matches(String ifMatch, long version) {
        return of(version).equals(ifMatch.strip());
    }
}
