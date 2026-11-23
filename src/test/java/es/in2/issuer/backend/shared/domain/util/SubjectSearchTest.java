package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/** EUD-255 AD-9: the one normalization of the subject, the same when stored and when searched. */
class SubjectSearchTest {

    @ParameterizedTest(name = "[{index}] \"{0}\" -> \"{1}\"")
    @CsvSource(delimiter = '|', value = {
            "María García López|maria garcia lopez",
            "IBÁÑEZ|ibanez",
            "Núria Puigdomènech|nuria puigdomenech",
            "Joan  Albert\tChías |joan albert chias",
            "François Müller|francois muller",
            "garcia|garcia"
    })
    void removesMarks_lowersAndCollapsesSpaces(String subject, String normalized) {
        assertThat(SubjectSearch.normalize(subject)).isEqualTo(normalized);
    }

    /** A decomposed accent (e + U+0301) and a precomposed one (U+00E9) are the same text to the search. */
    @Test
    void decomposedAndPrecomposedAccents_normalizeAlike() {
        assertThat(SubjectSearch.normalize("José")).isEqualTo(SubjectSearch.normalize("José")).isEqualTo("jose");
    }

    /** Locale.ROOT: the dotted capital I does not become the dotless one of a Turkish default locale. */
    @Test
    void lowerCase_doesNotDependOnTheDefaultLocale() {
        java.util.Locale previous = java.util.Locale.getDefault();
        try {
            java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"));
            assertThat(SubjectSearch.normalize("IGLESIAS")).isEqualTo("iglesias");
        } finally {
            java.util.Locale.setDefault(previous);
        }
    }

    @Test
    void noSubject_isNoSearchForm() {
        assertThat(SubjectSearch.normalize(null)).isNull();
    }
}
