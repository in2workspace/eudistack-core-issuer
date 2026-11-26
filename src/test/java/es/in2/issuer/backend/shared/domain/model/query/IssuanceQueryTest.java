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

    /** AD-5: the cursor of a search by identifier carries its fingerprint, never an unkeyed hash of the value. */
    @Test
    void digest_ofASearchByIdentifier_needsItsFingerprint_andDependsOnTypeAndFingerprint() {
        IssuanceQuery received = byIdentifier("colegiado", "28/12345");

        assertThatThrownBy(received::filterDigest).isInstanceOf(IllegalStateException.class);
        String digest = received.withIdentifierFingerprint(FINGERPRINT).filterDigest();
        assertThat(digest).isNotEqualTo(query(Set.of(), null, null, 50).filterDigest());
        assertThat(byIdentifier("colegiado", "other").withIdentifierFingerprint(FINGERPRINT).filterDigest())
                .as("the value does not count, only its fingerprint").isEqualTo(digest);
        assertThat(byIdentifier("dni", "28/12345").withIdentifierFingerprint(FINGERPRINT).filterDigest())
                .isNotEqualTo(digest);
        assertThat(received.withIdentifierFingerprint(OTHER_FINGERPRINT).filterDigest()).isNotEqualTo(digest);
    }

    /** AD-7: the identifier goes to the trace as received; AD-5: once fingerprinted, the value is gone. */
    @Test
    void theIdentifierSearched_isAFilterOfTheTrace_butNeverPrinted_andTheFingerprintDropsTheValue() {
        IssuanceQuery received = byIdentifier("dni", "12345678Z");
        IssuanceQuery fingerprinted = received.withIdentifierFingerprint(FINGERPRINT);

        assertThat(received.filters()).containsEntry("identifier_type", "dni").containsEntry("identifier", "12345678Z");
        assertThat(received.toString()).doesNotContain("12345678Z");
        assertThat(fingerprinted.identifier().value()).isNull();
        assertThat(fingerprinted.identifier().fingerprint()).isEqualTo(FINGERPRINT);
        assertThat(fingerprinted.filters()).doesNotContainKey("identifier");
        assertThat(fingerprinted.limit()).isEqualTo(received.limit());
    }

    @Test
    void aSearchByNameAndByIdentifier_atOnce_isRefused() {
        SearchIdentifierCriterion dni = SearchIdentifierCriterion.searched("dni", "12345678Z");
        IssuanceQuery byName = search("garcia");

        assertThatThrownBy(() -> new IssuanceQuery(Set.of(), null, null, 50, null, "garcia", dni))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> byName.withIdentifierFingerprint(FINGERPRINT))
                .isInstanceOf(IllegalStateException.class);
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

    private static final byte[] FINGERPRINT = new byte[32];
    private static final byte[] OTHER_FINGERPRINT = {1, 2, 3};

    private static IssuanceQuery byIdentifier(String type, String value) {
        return new IssuanceQuery(Set.of(), null, null, 50, null, null, SearchIdentifierCriterion.searched(type, value));
    }
}
