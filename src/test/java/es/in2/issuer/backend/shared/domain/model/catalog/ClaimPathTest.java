package es.in2.issuer.backend.shared.domain.model.catalog;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClaimPathTest {

    @Test
    void ClaimPath_withABlankSegment_isAccepted() {
        assertThat(ClaimPath.of("mandate", " ").segments()).containsExactly("mandate", " ");
    }

    @Test
    void ClaimPath_withANullSegment_isRejected() {
        List<String> segments = Arrays.asList("mandate", null);

        assertThatThrownBy(() -> new ClaimPath(segments)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void ClaimPath_withoutSegments_isRejected() {
        List<String> segments = List.of();

        assertThatThrownBy(() -> new ClaimPath(segments)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toString_listsTheSegments() {
        assertThat(ClaimPath.of("mandate", "mandatee", "firstName")).hasToString("[mandate, mandatee, firstName]");
    }

    @Test
    void toString_quotesBlankSegments() {
        assertThat(ClaimPath.of("")).hasToString("[\"\"]");
        assertThat(ClaimPath.of("givenName", " ")).hasToString("[givenName, \" \"]");
    }
}
