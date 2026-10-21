package es.in2.issuer.backend.shared.domain.model.catalog;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CatalogEntryChangeTest {

    private static final String DOCTORID = "doctorid.sd.1";
    private static final String URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";

    @Test
    void changes_ofACreatedEntry_hasNullBeforeEveryValue() {
        CatalogEntry created = entry(true, 0);

        Map<String, List<Object>> changes = CatalogEntryChange.created(created).changes();

        assertThat(changes).containsOnlyKeys(
                "schema_uri", "enabled", "delivery_modes", "validity", "subject", "search_identifiers");
        assertThat(changes.get("enabled")).containsExactly(null, true);
        assertThat(changes.get("schema_uri")).containsExactly(null, URI);
        assertThat(changes.get("delivery_modes")).containsExactly(null, List.of("email", "ui"));
        assertThat(changes.get("validity")).containsExactly(null,
                Map.of("default_days", 36500, "requester_can_set_dates", false));
        assertThat(changes.get("subject")).containsExactly(null,
                Map.of("fields", List.of(List.of("givenName"), List.of("familyName")), "separator", " "));
        assertThat(changes.get("search_identifiers")).containsExactly(null,
                List.of(Map.of("name", "colegiado", "field", List.of("personal_administrative_number"))));
    }

    @Test
    void changes_ofACreatedEntryWithoutSubject_leavesTheSubjectOut() {
        CatalogEntry full = entry(true, 0);
        CatalogEntry created = new CatalogEntry(DOCTORID, URI, true, full.deliveryModes(), full.validity(), null,
                full.searchIdentifiers(), 0, Instant.now(), Instant.now());

        assertThat(CatalogEntryChange.created(created).changes()).doesNotContainKey("subject");
    }

    @Test
    void changes_listsOnlyTheFieldsThatDiffer_asBeforeAfterPairs() {
        CatalogEntry before = entry(true, 3);
        CatalogEntry full = entry(true, 4);
        CatalogEntry after = new CatalogEntry(DOCTORID, URI, true, Set.of(DeliveryMode.UI),
                new CatalogEntry.Validity(100, true, 200), full.subject(), full.searchIdentifiers(), 4,
                Instant.now(), Instant.now());

        Map<String, List<Object>> changes = CatalogEntryChange.updated(before, after).changes();

        assertThat(changes).containsOnlyKeys("delivery_modes", "validity");
        assertThat(changes.get("delivery_modes")).containsExactly(List.of("email", "ui"), List.of("ui"));
        assertThat(changes.get("validity")).containsExactly(
                Map.of("default_days", 36500, "requester_can_set_dates", false),
                Map.of("default_days", 100, "requester_can_set_dates", true, "max_days", 200));
    }

    @Test
    void changes_ofAnEntryThatBecameCompleted_showsTheValuesTheFileGave() {
        CatalogEntry unfilled = new CatalogEntry(DOCTORID, null, true, null, null, null, List.of(), 0,
                Instant.now(), Instant.now());

        Map<String, List<Object>> changes = CatalogEntryChange.between(unfilled, entry(true, 1)).changes();

        assertThat(changes.get("delivery_modes")).containsExactly(null, List.of("email", "ui"));
        assertThat(changes.get("schema_uri")).containsExactly(null, URI);
        assertThat(changes).doesNotContainKey("enabled");
    }

    @Test
    void between_derivesTheOperationFromTheEnabledFlag() {
        assertThat(CatalogEntryChange.between(entry(true, 1), entry(false, 2)).operation())
                .isEqualTo(CatalogEntryChange.Operation.DISABLE);
        assertThat(CatalogEntryChange.between(entry(false, 1), entry(true, 2)).operation())
                .isEqualTo(CatalogEntryChange.Operation.ENABLE);
        assertThat(CatalogEntryChange.between(entry(true, 1), entry(true, 2)).operation())
                .isEqualTo(CatalogEntryChange.Operation.UPDATE);
    }

    @Test
    void operationValues_areTheOnesTheAuditEventDocuments() {
        assertThat(CatalogEntryChange.Operation.values())
                .extracting(CatalogEntryChange.Operation::value)
                .containsExactly("Create", "Update", "Enable", "Disable");
    }

    @Test
    void credentialConfigurationId_comesFromTheEntryAsStored() {
        CatalogEntryChange change = CatalogEntryChange.updated(entry(true, 3), entry(true, 4));

        assertThat(change.credentialConfigurationId()).isEqualTo(DOCTORID);
    }

    private static CatalogEntry entry(boolean enabled, long version) {
        return new CatalogEntry(DOCTORID, URI, enabled, Set.of(DeliveryMode.EMAIL, DeliveryMode.UI),
                new CatalogEntry.Validity(36500, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "),
                List.of(new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("personal_administrative_number"))),
                version, Instant.now(), Instant.now());
    }
}
