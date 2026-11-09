package es.in2.issuer.backend.shared.domain.model.catalog;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class CatalogEntryETagTest {

    @Test
    void of_isTheVersionAsAStrongTag() {
        assertThat(CatalogEntryETag.of(3)).isEqualTo("\"3\"");
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"3\"", " \"3\" ", "\"9\", \"3\"", "\"3\",\"9\""})
    void matches_whenTheTagOrOneOfTheListedTagsIsTheCurrentOne_isTrue(String ifMatch) {
        assertThat(CatalogEntryETag.matches(ifMatch, 3)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"2\"", "3", "W/\"3\"", "\"9\", W/\"3\"", "\"9\", \"2\"", "\"3"})
    void matches_whenNoListedTagIsStronglyTheCurrentOne_isFalse(String ifMatch) {
        assertThat(CatalogEntryETag.matches(ifMatch, 3)).isFalse();
    }
}
