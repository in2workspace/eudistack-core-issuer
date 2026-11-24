package es.in2.issuer.backend.shared.domain.model.query;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.REVOKED;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** EUD-255 AD-1: the digest the cursor carries depends on the filters and only on them. */
class IssuanceQueryTest {

    @Test
    void digest_doesNotDependOnTheOrderOfTheStates() {
        Set<CredentialStatusEnum> validThenRevoked = new LinkedHashSet<>(List.of(VALID, REVOKED));
        Set<CredentialStatusEnum> revokedThenValid = new LinkedHashSet<>(List.of(REVOKED, VALID));

        assertThat(query(validThenRevoked, null, null, 50).filterDigest())
                .isEqualTo(query(revokedThenValid, null, null, 50).filterDigest());
    }

    @Test
    void digest_doesNotDependOnThePageSize() {
        assertThat(query(Set.of(VALID), "doctor.sd.1", null, 10).filterDigest())
                .isEqualTo(query(Set.of(VALID), "doctor.sd.1", null, 200).filterDigest());
    }

    @Test
    void digest_changesWithEveryFilter() {
        String none = query(Set.of(), null, null, 50).filterDigest();

        assertThat(query(Set.of(VALID), null, null, 50).filterDigest()).isNotEqualTo(none);
        assertThat(query(Set.of(), "doctor.sd.1", null, 50).filterDigest()).isNotEqualTo(none);
        assertThat(query(Set.of(), null, "sandbox", 50).filterDigest()).isNotEqualTo(none);
    }

    /** AD-9: the cursor of a search by name serves the same text however it is written, and no other. */
    @Test
    void digest_ofASearchByName_dependsOnTheComparedFormOfTheText() {
        String listing = query(Set.of(), null, null, 50).filterDigest();
        String garcia = search("garcia").filterDigest();

        assertThat(garcia).isNotEqualTo(listing);
        assertThat(search("  GARCÍA ").filterDigest()).isEqualTo(garcia);
        assertThat(search("garces").filterDigest()).isNotEqualTo(garcia);
    }

    /** AD-7: the text searched goes to the trace as given; AD-5: nowhere else, not even in a log of the query. */
    @Test
    void theTextSearched_isAFilterOfTheTrace_butNeverPrinted() {
        IssuanceQuery search = search("María García");

        assertThat(search.filters()).containsEntry("subject", "María García");
        assertThat(search.toString()).doesNotContain("María").doesNotContain("García");
        assertThat(query(Set.of(), null, null, 50).filters()).doesNotContainKey("subject");
    }

    @Test
    void noStates_meansEveryState() {
        assertThat(query(null, null, null, 50).lifeCycleStatuses()).isEmpty();
        assertThat(IssuanceQuery.firstPage().limit()).isEqualTo(IssuanceQuery.DEFAULT_LIMIT);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 201})
    void aLimitOutOfRange_isRefused(int limit) {
        assertThatThrownBy(() -> query(Set.of(), null, null, limit)).isInstanceOf(IllegalArgumentException.class);
    }

    private static IssuanceQuery query(Set<CredentialStatusEnum> states, String entry, String tenant, int limit) {
        return new IssuanceQuery(states, entry, tenant, limit, null);
    }

    private static IssuanceQuery search(String subject) {
        return new IssuanceQuery(Set.of(), null, null, 50, null, subject);
    }
}
