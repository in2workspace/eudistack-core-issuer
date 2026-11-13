package es.in2.issuer.backend.shared.domain.model.searchidentifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SearchIdentifierFingerprinterTest {

    private static final byte[] KEY = "a-tenant-secret-key-of-32-bytes!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] OTHER_KEY = "another-tenant-key-of-32-bytes!!".getBytes(StandardCharsets.UTF_8);
    private static final CatalogEntry.SearchIdentifier DNI =
            new CatalogEntry.SearchIdentifier("dni", ClaimPath.of("credentialSubject", "dni"));
    private static final CatalogEntry.SearchIdentifier COLEGIADO =
            new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("credentialSubject", "colegiado"));

    private final ObjectMapper objectMapper = new ObjectMapper();

    private JsonNode attestation(String json) throws Exception {
        return objectMapper.readTree(json);
    }

    @Test
    void normalize_removesEveryWhitespace_upperCases_andKeepsTheOtherCharacters() {
        assertThat(SearchIdentifierFingerprinter.normalize(" 28 / 12345 ")).isEqualTo("28/12345");
        assertThat(SearchIdentifierFingerprinter.normalize("12345678z")).isEqualTo("12345678Z");
        assertThat(SearchIdentifierFingerprinter.normalize("12\t345\n678-z")).isEqualTo("12345678-Z");
        // A non-breaking space is a space too.
        assertThat(SearchIdentifierFingerprinter.normalize("12 345")).isEqualTo("12345");
        assertThat(SearchIdentifierFingerprinter.normalize("ñandú")).isEqualTo("ÑANDÚ");
        assertThat(SearchIdentifierFingerprinter.normalize(null)).isEmpty();
    }

    @Test
    void normalize_usesTheRootLocale_soTheResultDoesNotDependOnTheServer() {
        java.util.Locale previous = java.util.Locale.getDefault();
        try {
            java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr"));
            assertThat(SearchIdentifierFingerprinter.normalize("i")).isEqualTo("I");
        } finally {
            java.util.Locale.setDefault(previous);
        }
    }

    @Test
    void fingerprint_isTheHmacSha256OfTheNormalizedValueWithTheTenantKey() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        byte[] expected = mac.doFinal("28/12345".getBytes(StandardCharsets.UTF_8));

        assertThat(SearchIdentifierFingerprinter.fingerprint(KEY, "28 / 12345")).hasValueSatisfying(
                fingerprint -> assertThat(fingerprint).hasSize(32).isEqualTo(expected));
    }

    @Test
    void fingerprint_isTheSameForTheSameValueWrittenDifferently_andDiffersWithAnotherKey() {
        byte[] issued = SearchIdentifierFingerprinter.fingerprint(KEY, "12345678Z").orElseThrow();

        assertThat(SearchIdentifierFingerprinter.fingerprint(KEY, " 1234 5678 z")).hasValue(issued);
        assertThat(SearchIdentifierFingerprinter.fingerprint(OTHER_KEY, "12345678Z").orElseThrow()).isNotEqualTo(issued);
        assertThat(SearchIdentifierFingerprinter.fingerprint(KEY, "12345678A").orElseThrow()).isNotEqualTo(issued);
    }

    @Test
    void fingerprint_ofAValueThatNormalizesToNothing_isEmpty() {
        assertThat(SearchIdentifierFingerprinter.fingerprint(KEY, "  \t ")).isEmpty();
        assertThat(SearchIdentifierFingerprinter.fingerprint(KEY, null)).isEmpty();
    }

    @Test
    void fingerprint_needsAKeyOf32BytesOrMore() {
        byte[] shortKey = "short".getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> SearchIdentifierFingerprinter.fingerprint(shortKey, "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SearchIdentifierFingerprinter.fingerprint(null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fingerprintsOf_oneForEachDeclaredIdentifierTheAttestationContains() throws Exception {
        JsonNode both = attestation("{\"credentialSubject\":{\"dni\":\"12345678Z\",\"colegiado\":\"28/12345\"}}");

        List<SearchIdentifierFingerprint> fingerprints =
                SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI, COLEGIADO), both);

        assertThat(fingerprints).extracting(SearchIdentifierFingerprint::identifierType)
                .containsExactly("dni", "colegiado");
        assertThat(fingerprints.getFirst().fingerprint())
                .isEqualTo(SearchIdentifierFingerprinter.fingerprint(KEY, "12345678Z").orElseThrow());
    }

    @Test
    void fingerprintsOf_withoutTheData_hasNoFingerprintForIt() throws Exception {
        JsonNode onlyDni = attestation("{\"credentialSubject\":{\"dni\":\"12345678Z\",\"colegiado\":\"  \"}}");
        JsonNode none = attestation("{\"credentialSubject\":{}}");
        JsonNode notAnObject = attestation("{\"credentialSubject\":\"x\"}");

        assertThat(SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI, COLEGIADO), onlyDni))
                .extracting(SearchIdentifierFingerprint::identifierType).containsExactly("dni");
        assertThat(SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI, COLEGIADO), none)).isEmpty();
        assertThat(SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI), notAnObject)).isEmpty();
        assertThat(SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(), onlyDni)).isEmpty();
    }

    @Test
    void fingerprintsOf_takesANumberAsItsText_butNotAnObjectOrAList() throws Exception {
        JsonNode numeric = attestation("{\"credentialSubject\":{\"colegiado\":2812345,\"dni\":{\"value\":\"1\"}}}");

        List<SearchIdentifierFingerprint> fingerprints =
                SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI, COLEGIADO), numeric);

        assertThat(fingerprints).extracting(SearchIdentifierFingerprint::identifierType).containsExactly("colegiado");
        assertThat(fingerprints.getFirst().fingerprint())
                .isEqualTo(SearchIdentifierFingerprinter.fingerprint(KEY, "2812345").orElseThrow());
    }

    @Test
    void fingerprintsOf_twoIdentifiersWithOneName_keepTheFirstThatHasAValue() throws Exception {
        CatalogEntry.SearchIdentifier dniElsewhere =
                new CatalogEntry.SearchIdentifier("dni", ClaimPath.of("credentialSubject", "nif"));
        JsonNode onlyNif = attestation("{\"credentialSubject\":{\"nif\":\"B12345678\"}}");
        JsonNode both = attestation("{\"credentialSubject\":{\"dni\":\"12345678Z\",\"nif\":\"B12345678\"}}");

        assertThat(SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI, dniElsewhere), onlyNif))
                .singleElement()
                .satisfies(f -> assertThat(f.fingerprint())
                        .isEqualTo(SearchIdentifierFingerprinter.fingerprint(KEY, "B12345678").orElseThrow()));
        assertThat(SearchIdentifierFingerprinter.fingerprintsOf(KEY, List.of(DNI, dniElsewhere), both))
                .singleElement()
                .satisfies(f -> assertThat(f.fingerprint())
                        .isEqualTo(SearchIdentifierFingerprinter.fingerprint(KEY, "12345678Z").orElseThrow()));
    }

    @Test
    void keyId_identifiesTheKeyWithoutRevealingIt() {
        String keyId = SearchIdentifierFingerprinter.keyId(KEY);

        assertThat(keyId).hasSize(16).isEqualTo(SearchIdentifierFingerprinter.keyId(KEY.clone()))
                .isNotEqualTo(SearchIdentifierFingerprinter.keyId(OTHER_KEY));
        assertThat(new String(KEY, StandardCharsets.UTF_8)).doesNotContain(keyId);
    }

    @Test
    void aFingerprint_isNeverPrinted_andIsComparedByValue() {
        byte[] bytes = SearchIdentifierFingerprinter.fingerprint(KEY, "12345678Z").orElseThrow();
        SearchIdentifierFingerprint fingerprint = new SearchIdentifierFingerprint("dni", bytes);

        assertThat(fingerprint).isEqualTo(new SearchIdentifierFingerprint("dni", bytes.clone()))
                .hasSameHashCodeAs(new SearchIdentifierFingerprint("dni", bytes.clone()))
                .isNotEqualTo(new SearchIdentifierFingerprint("colegiado", bytes));
        assertThat(fingerprint.toString()).contains("redacted").doesNotContain(java.util.HexFormat.of().formatHex(bytes));
        assertThatThrownBy(() -> new SearchIdentifierFingerprint("dni", new byte[3]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
