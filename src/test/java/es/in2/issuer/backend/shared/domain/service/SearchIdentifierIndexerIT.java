package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

/**
 * The search identifier fingerprints against a real Postgres, the real transaction manager and the local tenant key
 * (EUD-267): AC-14 of EUD-254 (a fingerprint per identifier the attestation contains, none without the data, no
 * process without its fingerprints) and AC-10 of EUD-169 (what was already issued is fingerprinted in the
 * background when an identifier is added).
 */
@ActiveProfiles("local")
// Its own context (local profile, spied store): closed after the class, so the test JVM does not keep it cached.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = "issuer.search-identifiers.local-key-seed=it-local-seed-of-at-least-thirty-two-chars")
class SearchIdentifierIndexerIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";
    private static final String SCHEMA = "\"" + TENANT + SCHEMA_SUFFIX + "\"";
    private static final CatalogEntry.SearchIdentifier DNI =
            new CatalogEntry.SearchIdentifier("dni", ClaimPath.of("credentialSubject", "dni"));
    private static final CatalogEntry.SearchIdentifier COLEGIADO =
            new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("credentialSubject", "colegiado"));

    @Autowired private SearchIdentifierIndexer indexer;
    @Autowired private CatalogEntryPort catalogEntryPort;
    @Autowired private TenantSecretKeyPort tenantSecretKeyPort;
    @MockitoSpyBean private SearchIdentifierStore store;

    private <T> T inTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
    }

    private static String type() {
        return "eud267." + UUID.randomUUID().toString().substring(0, 8);
    }

    private CatalogEntry entry(String type, List<CatalogEntry.SearchIdentifier> identifiers) {
        return inTenant(catalogEntryPort.insert(
                new CatalogEntry(type, null, false, null, null, null, identifiers, 0, null, null)));
    }

    private void changeIdentifiers(CatalogEntry current, List<CatalogEntry.SearchIdentifier> identifiers) {
        CatalogEntry changed = new CatalogEntry(current.credentialConfigurationId(), current.schemaUri(),
                current.enabled(), current.deliveryModes(), current.validity(), current.subject(), identifiers,
                current.version(), current.created(), current.updated());
        assertThat(inTenant(catalogEntryPort.updateIfVersion(changed, current.version()))).isPresent();
    }

    private static Issuance issuance(String type, String subject) {
        return Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialType(type)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialFormat("jwt_vc_json")
                .organizationIdentifier("VATES-IT")
                .credentialDataSet("{\"credentialSubject\":" + subject + "}")
                .email("holder@example.org")
                .delivery("email")
                .build();
    }

    /** identifier_type → fingerprint of a process, read straight from the table. */
    private Map<String, byte[]> fingerprintsOf(UUID issuanceId) {
        Map<String, byte[]> rows = new HashMap<>();
        databaseClient.sql("SELECT identifier_type, fingerprint FROM " + SCHEMA
                        + ".issuance_search_identifier WHERE issuance_id = :id")
                .bind("id", issuanceId)
                .map((row, metadata) -> Map.entry(row.get("identifier_type", String.class), row.get("fingerprint", byte[].class)))
                .all()
                .doOnNext(e -> rows.put(e.getKey(), e.getValue()))
                .blockLast();
        return rows;
    }

    private long processes(UUID issuanceId) {
        return databaseClient.sql("SELECT count(*) AS n FROM " + SCHEMA + ".issuance WHERE issuance_id = :id")
                .bind("id", issuanceId)
                .map((row, metadata) -> row.get("n", Long.class))
                .one()
                .block();
    }

    private byte[] expected(String value) {
        byte[] key = inTenant(tenantSecretKeyPort.keyOf(TENANT));
        return SearchIdentifierFingerprinter.fingerprint(key, value).orElseThrow();
    }

    @Test
    void anEntryThatDeclaresDniAndColegiado_anAttestationWithBoth_getsAFingerprintOfEach() {
        // AC-14 of EUD-254.
        String type = type();
        entry(type, List.of(DNI, COLEGIADO));
        Issuance issued = issuance(type, "{\"dni\":\"12345678Z\",\"colegiado\":\"28 / 12345\"}");

        inTenant(indexer.saveWithFingerprints(issued));

        Map<String, byte[]> fingerprints = fingerprintsOf(issued.getIssuanceId());
        assertThat(fingerprints).containsOnlyKeys("dni", "colegiado");
        assertThat(fingerprints.get("dni")).isEqualTo(expected("12345678z"));
        // Normalized as the client searches it: 28/12345.
        assertThat(fingerprints.get("colegiado")).isEqualTo(expected("28/12345"));
        // Never the value in clear.
        assertThat(new String(fingerprints.get("dni"), StandardCharsets.ISO_8859_1)).doesNotContain("12345678");
    }

    @Test
    void anAttestationWithoutTheData_getsNoFingerprintForIt_andAnEntryWithoutIdentifiers_none() {
        String type = type();
        entry(type, List.of(DNI, COLEGIADO));
        Issuance onlyDni = issuance(type, "{\"dni\":\"12345678Z\"}");
        String withoutIdentifiers = type();
        entry(withoutIdentifiers, List.of());
        Issuance plain = issuance(withoutIdentifiers, "{\"dni\":\"12345678Z\"}");

        inTenant(indexer.saveWithFingerprints(onlyDni));
        inTenant(indexer.saveWithFingerprints(plain));

        assertThat(fingerprintsOf(onlyDni.getIssuanceId())).containsOnlyKeys("dni");
        assertThat(processes(plain.getIssuanceId())).isOne();
        assertThat(fingerprintsOf(plain.getIssuanceId())).isEmpty();
    }

    @Test
    void whenItsFingerprintsCannotBeStored_theProcessIsNotStoredEither() {
        // NFR of EUD-254: processes stored without their fingerprints = 0. The second write is forced to fail.
        String type = type();
        entry(type, List.of(DNI));
        Issuance issued = issuance(type, "{\"dni\":\"12345678Z\"}");
        doReturn(Mono.error(new IllegalStateException("fingerprint write failed")))
                .when(store).insertAll(eq(issued.getIssuanceId()), anyList());

        assertThatThrownBy(() -> inTenant(indexer.saveWithFingerprints(issued)))
                .hasMessageContaining("fingerprint write failed");

        assertThat(processes(issued.getIssuanceId())).isZero();
        assertThat(fingerprintsOf(issued.getIssuanceId())).isEmpty();
    }

    @Test
    void anIdentifierAddedToAnEntry_isFingerprintedInTheBackgroundForWhatWasAlreadyIssued_andRemovedWithIt() {
        // AC-10 of EUD-169.
        String type = type();
        CatalogEntry entry = entry(type, List.of());
        Issuance first = issuance(type, "{\"dni\":\"11111111H\"}");
        Issuance second = issuance(type, "{\"dni\":\"22222222J\",\"colegiado\":\"28/1\"}");
        Issuance withoutDni = issuance(type, "{\"colegiado\":\"28/2\"}");
        inTenant(indexer.saveWithFingerprints(first));
        inTenant(indexer.saveWithFingerprints(second));
        inTenant(indexer.saveWithFingerprints(withoutDni));
        inTenant(indexer.reindexTenant());
        assertThat(fingerprintsOf(first.getIssuanceId())).isEmpty();

        changeIdentifiers(entry, List.of(DNI));
        inTenant(indexer.reindexTenant());

        assertThat(fingerprintsOf(first.getIssuanceId())).containsOnlyKeys("dni");
        assertThat(fingerprintsOf(first.getIssuanceId()).get("dni")).isEqualTo(expected("11111111H"));
        assertThat(fingerprintsOf(second.getIssuanceId())).containsOnlyKeys("dni");
        assertThat(fingerprintsOf(withoutDni.getIssuanceId())).isEmpty();

        // Nothing changed: a second run leaves everything as it is.
        inTenant(indexer.reindexTenant());
        assertThat(fingerprintsOf(second.getIssuanceId())).containsOnlyKeys("dni");

        changeIdentifiers(inTenant(catalogEntryPort.findById(type)), List.of());
        inTenant(indexer.reindexTenant());

        assertThat(fingerprintsOf(first.getIssuanceId())).isEmpty();
        assertThat(fingerprintsOf(second.getIssuanceId())).isEmpty();
    }
}
