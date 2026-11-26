package es.in2.issuer.backend.shared.domain.util;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The form of the subject that the search by name compares (EUD-255 AD-9): without accents or other marks, in lower
 * case and with single spaces. The same function is applied when the subject is stored and to the text searched, so
 * a search for {@code "garcia"} finds {@code "García"}. Changing it requires backfilling every stored subject.
 */
public final class SubjectSearch {

    private static final Pattern MARKS = Pattern.compile("\\p{M}");
    private static final Pattern SPACES = Pattern.compile("\\s+");

    private SubjectSearch() {
    }

    /** The normalized subject, or {@code null} for no subject. */
    public static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String withoutMarks = MARKS.matcher(Normalizer.normalize(value, Normalizer.Form.NFD)).replaceAll("");
        return SPACES.matcher(withoutMarks.toLowerCase(Locale.ROOT).trim()).replaceAll(" ");
    }
}
