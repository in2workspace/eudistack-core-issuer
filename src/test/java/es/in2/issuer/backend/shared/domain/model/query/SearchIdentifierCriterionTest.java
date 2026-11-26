package es.in2.issuer.backend.shared.domain.model.query;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** EUD-255 AD-4 and AD-5: a search by identifier carries its value or its fingerprint, and prints neither. */
class SearchIdentifierCriterionTest {

    private static final byte[] FINGERPRINT = {1, 2, 3, 4};

    @Test
    void itHasEitherTheValueOrTheFingerprint_neverBothNorNeither() {
        assertThatThrownBy(() -> new SearchIdentifierCriterion("dni", "12345678Z", FINGERPRINT))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SearchIdentifierCriterion("dni", null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theFingerprint_replacesTheValue() {
        SearchIdentifierCriterion fingerprinted = SearchIdentifierCriterion.searched("dni", "12345678Z")
                .fingerprinted(FINGERPRINT);

        assertThat(fingerprinted.type()).isEqualTo("dni");
        assertThat(fingerprinted.value()).isNull();
        assertThat(fingerprinted.isFingerprinted()).isTrue();
        assertThat(fingerprinted.fingerprint()).containsExactly(FINGERPRINT);
    }

    @Test
    void theFingerprint_cannotBeChangedFromOutside() {
        byte[] computed = FINGERPRINT.clone();
        SearchIdentifierCriterion fingerprinted = SearchIdentifierCriterion.searched("dni", "x").fingerprinted(computed);

        computed[0] = 9;
        fingerprinted.fingerprint()[1] = 9;

        assertThat(fingerprinted.fingerprint()).containsExactly(FINGERPRINT);
    }

    @Test
    void twoCriteria_areEqualByTheirContent() {
        assertThat(SearchIdentifierCriterion.searched("dni", "x").fingerprinted(FINGERPRINT.clone()))
                .isEqualTo(SearchIdentifierCriterion.searched("dni", "y").fingerprinted(FINGERPRINT.clone()))
                .hasSameHashCodeAs(SearchIdentifierCriterion.searched("dni", "y").fingerprinted(FINGERPRINT.clone()));
        assertThat(SearchIdentifierCriterion.searched("dni", "x"))
                .isNotEqualTo(SearchIdentifierCriterion.searched("dni", "y"));
    }

    @Test
    void itPrintsNeitherTheValueNorTheFingerprint() {
        SearchIdentifierCriterion received = SearchIdentifierCriterion.searched("dni", "12345678Z");

        assertThat(received.toString()).contains("dni").doesNotContain("12345678Z");
        assertThat(received.fingerprinted(FINGERPRINT).toString()).doesNotContain("AQIDBA");
    }

    @Test
    void theTextOfTheFingerprint_needsOne() {
        SearchIdentifierCriterion received = SearchIdentifierCriterion.searched("dni", "x");

        assertThatThrownBy(received::fingerprintText).isInstanceOf(IllegalStateException.class);
        assertThat(SearchIdentifierCriterion.searched("dni", "x").fingerprinted(FINGERPRINT).fingerprintText())
                .isEqualTo("AQIDBA");
    }
}
