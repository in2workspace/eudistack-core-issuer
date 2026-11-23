package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprint;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierIndexState;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore.StoredAttestation;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@code issuance_search_identifier} and {@code search_identifier_index_state} (V20) against a real Postgres. */
class R2dbcSearchIdentifierStoreIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String SCHEMA = "\"" + TENANT + SCHEMA_SUFFIX + "\"";
    private static final String KEY_ID = "0011223344556677";
    private static final String ROTATED_KEY_ID = "8899aabbccddeeff";

    @Autowired private R2dbcSearchIdentifierStore store;
    @Autowired private TransactionalOperator transactionalOperator;

    private <T> T inTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
    }

    private <T> List<T> inTenant(Flux<T> flux) {
        return flux.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).collectList().block();
    }

    private static String type() {
        return "store." + UUID.randomUUID().toString().substring(0, 8);
    }

    private UUID process(String type, String dataSet) {
        UUID id = UUID.randomUUID();
        databaseClient.sql("INSERT INTO " + SCHEMA + ".issuance (issuance_id, credential_type, credential_data_set) "
                        + "VALUES (:id, :type, :data)")
                .bind("id", id).bind("type", type).bind("data", dataSet)
                .then().block();
        return id;
    }

    private static SearchIdentifierFingerprint fingerprint(String type, int seed) {
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) seed);
        return new SearchIdentifierFingerprint(type, bytes);
    }

    private List<String> typesOf(UUID issuanceId) {
        return databaseClient.sql("SELECT identifier_type FROM " + SCHEMA
                        + ".issuance_search_identifier WHERE issuance_id = :id ORDER BY identifier_type")
                .bind("id", issuanceId)
                .map((row, metadata) -> row.get("identifier_type", String.class))
                .all().collectList().block();
    }

    @Test
    void insertAll_andReplaceAll_keepOneFingerprintPerIdentifierOfAProcess() {
        UUID id = process(type(), "{}");

        inTenant(store.insertAll(id, KEY_ID, List.of(fingerprint("dni", 1), fingerprint("colegiado", 2))));
        assertThat(typesOf(id)).containsExactly("colegiado", "dni");

        inTenant(store.replaceAll(id, KEY_ID, List.of(fingerprint("dni", 3))));
        assertThat(typesOf(id)).containsExactly("dni");

        inTenant(store.replaceAll(id, KEY_ID, List.of()));
        assertThat(typesOf(id)).isEmpty();
    }

    /**
     * Two instances recompute the same process at once (the background calculation runs on the same cron in each): the
     * second waits for the first one's DELETE, does not see the rows the first then inserted, and must overwrite them
     * instead of failing on the primary key.
     */
    @Test
    void replaceAll_inTwoConcurrentTransactions_bothCommitWithOneFingerprintPerIdentifier() {
        UUID id = process(type(), "{}");
        inTenant(store.insertAll(id, ROTATED_KEY_ID, List.of(fingerprint("dni", 1))));

        Mono<Void> first = transactionalOperator.transactional(
                store.replaceAll(id, KEY_ID, List.of(fingerprint("dni", 2)))
                        .then(Mono.delay(Duration.ofMillis(800)).then()));
        Mono<Void> second = Mono.delay(Duration.ofMillis(200))
                .then(transactionalOperator.transactional(store.replaceAll(id, KEY_ID, List.of(fingerprint("dni", 2)))));

        inTenant(Mono.when(first, second));

        assertThat(typesOf(id)).containsExactly("dni");
        assertThat(inTenant(store.processesWithAnotherKey(typeOf(id), KEY_ID, null, 10))).isEmpty();
    }

    private String typeOf(UUID issuanceId) {
        return databaseClient.sql("SELECT credential_type FROM " + SCHEMA + ".issuance WHERE issuance_id = :id")
                .bind("id", issuanceId)
                .map((row, metadata) -> row.get("credential_type", String.class))
                .one().block();
    }

    @Test
    void aProcessHasAtMostOneFingerprintPerIdentifier_andTheyGoWithIt() {
        UUID id = process(type(), "{}");
        inTenant(store.insertAll(id, KEY_ID, List.of(fingerprint("dni", 1))));

        Mono<Void> secondOfTheSameType = store.insertAll(id, KEY_ID, List.of(fingerprint("dni", 2)));
        assertThatThrownBy(() -> inTenant(secondOfTheSameType))
                .isInstanceOf(RuntimeException.class);

        databaseClient.sql("DELETE FROM " + SCHEMA + ".issuance WHERE issuance_id = :id").bind("id", id).then().block();
        assertThat(typesOf(id)).isEmpty();
    }

    @Test
    void deleteAllOfType_onlyTouchesTheProcessesOfThatType() {
        String type = type();
        UUID ofType = process(type, "{}");
        UUID ofAnother = process(type(), "{}");
        inTenant(store.insertAll(ofType, KEY_ID, List.of(fingerprint("dni", 1))));
        inTenant(store.insertAll(ofAnother, KEY_ID, List.of(fingerprint("dni", 1))));

        inTenant(store.deleteAllOfType(type));

        assertThat(typesOf(ofType)).isEmpty();
        assertThat(typesOf(ofAnother)).containsExactly("dni");
    }

    @Test
    void processesOfType_pagesByAscendingId_withTheStoredData() {
        String type = type();
        List<UUID> ids = List.of(process(type, "{\"a\":1}"), process(type, "{\"a\":2}"), process(type, "{\"a\":3}"));
        process(type(), "{}");

        List<StoredAttestation> first = inTenant(store.processesOfType(type, null, 2));
        List<StoredAttestation> rest = inTenant(store.processesOfType(type, first.getLast().issuanceId(), 2));

        // Postgres orders uuids its own way (not as java.util.UUID does): the pages do not overlap and cover all.
        assertThat(first).hasSize(2);
        assertThat(rest).hasSize(1);
        assertThat(java.util.stream.Stream.concat(first.stream(), rest.stream()).map(StoredAttestation::issuanceId))
                .containsExactlyInAnyOrderElementsOf(ids);
        assertThat(first.getFirst().credentialDataSet()).startsWith("{\"a\":");
    }

    @Test
    void processesWithAnotherKey_findsOnlyTheProcessesOfTheTypeWithAFingerprintOfAnotherKey() {
        String type = type();
        UUID current = process(type, "{\"a\":1}");
        UUID rotated = process(type, "{\"a\":2}");
        UUID partlyRotated = process(type, "{\"a\":3}");
        UUID withoutFingerprints = process(type, "{\"a\":4}");
        UUID rotatedOfAnotherType = process(type(), "{}");
        inTenant(store.insertAll(current, ROTATED_KEY_ID, List.of(fingerprint("dni", 1))));
        inTenant(store.insertAll(rotated, KEY_ID, List.of(fingerprint("dni", 2))));
        inTenant(store.insertAll(partlyRotated, ROTATED_KEY_ID, List.of(fingerprint("dni", 3))));
        inTenant(store.insertAll(partlyRotated, KEY_ID, List.of(fingerprint("colegiado", 3))));
        inTenant(store.insertAll(rotatedOfAnotherType, KEY_ID, List.of(fingerprint("dni", 4))));

        List<StoredAttestation> found = inTenant(store.processesWithAnotherKey(type, ROTATED_KEY_ID, null, 10));

        assertThat(found).extracting(StoredAttestation::issuanceId)
                .containsExactlyInAnyOrder(rotated, partlyRotated)
                .doesNotContain(current, withoutFingerprints, rotatedOfAnotherType);
        assertThat(found).allSatisfy(process -> assertThat(process.credentialDataSet()).startsWith("{\"a\":"));
    }

    @Test
    void processesWithAnotherKey_noneLeftOnceReplacedWithTheCurrentKey_andPagesAfterAnId() {
        String type = type();
        UUID first = process(type, "{}");
        UUID second = process(type, "{}");
        inTenant(store.insertAll(first, KEY_ID, List.of(fingerprint("dni", 1))));
        inTenant(store.insertAll(second, KEY_ID, List.of(fingerprint("dni", 2))));

        List<StoredAttestation> page = inTenant(store.processesWithAnotherKey(type, ROTATED_KEY_ID, null, 1));
        List<StoredAttestation> next =
                inTenant(store.processesWithAnotherKey(type, ROTATED_KEY_ID, page.getFirst().issuanceId(), 1));
        assertThat(java.util.stream.Stream.concat(page.stream(), next.stream()).map(StoredAttestation::issuanceId))
                .containsExactlyInAnyOrder(first, second);

        inTenant(store.replaceAll(first, ROTATED_KEY_ID, List.of(fingerprint("dni", 5))));
        inTenant(store.replaceAll(second, ROTATED_KEY_ID, List.of(fingerprint("dni", 6))));
        assertThat(inTenant(store.processesWithAnotherKey(type, ROTATED_KEY_ID, null, 10))).isEmpty();
    }

    @Test
    void theIndexState_isSavedAndOverwrittenPerEntry() {
        String type = type();

        inTenant(store.saveState(new SearchIdentifierIndexState(type, "[]", null)));
        inTenant(store.saveState(new SearchIdentifierIndexState(type, "[{\"dni\":[\"x\"]}]", "0011223344556677")));

        assertThat(inTenant(store.findAllStates()))
                .filteredOn(state -> state.credentialConfigurationId().equals(type))
                .containsExactly(new SearchIdentifierIndexState(type, "[{\"dni\":[\"x\"]}]", "0011223344556677"));
    }
}
