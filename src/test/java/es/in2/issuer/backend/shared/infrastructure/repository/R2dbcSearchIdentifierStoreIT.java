package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprint;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierIndexState;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore.StoredAttestation;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

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

    @Autowired private R2dbcSearchIdentifierStore store;

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

        inTenant(store.insertAll(id, List.of(fingerprint("dni", 1), fingerprint("colegiado", 2))));
        assertThat(typesOf(id)).containsExactly("colegiado", "dni");

        inTenant(store.replaceAll(id, List.of(fingerprint("dni", 3))));
        assertThat(typesOf(id)).containsExactly("dni");

        inTenant(store.replaceAll(id, List.of()));
        assertThat(typesOf(id)).isEmpty();
    }

    @Test
    void aProcessHasAtMostOneFingerprintPerIdentifier_andTheyGoWithIt() {
        UUID id = process(type(), "{}");
        inTenant(store.insertAll(id, List.of(fingerprint("dni", 1))));

        assertThatThrownBy(() -> inTenant(store.insertAll(id, List.of(fingerprint("dni", 2)))))
                .isInstanceOf(RuntimeException.class);

        databaseClient.sql("DELETE FROM " + SCHEMA + ".issuance WHERE issuance_id = :id").bind("id", id).then().block();
        assertThat(typesOf(id)).isEmpty();
    }

    @Test
    void deleteAllOfType_onlyTouchesTheProcessesOfThatType() {
        String type = type();
        UUID ofType = process(type, "{}");
        UUID ofAnother = process(type(), "{}");
        inTenant(store.insertAll(ofType, List.of(fingerprint("dni", 1))));
        inTenant(store.insertAll(ofAnother, List.of(fingerprint("dni", 1))));

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
    void theIndexState_isSavedAndOverwrittenPerEntry() {
        String type = type();

        inTenant(store.saveState(new SearchIdentifierIndexState(type, "[]", null)));
        inTenant(store.saveState(new SearchIdentifierIndexState(type, "[{\"dni\":[\"x\"]}]", "0011223344556677")));

        assertThat(inTenant(store.findAllStates()))
                .filteredOn(state -> state.credentialConfigurationId().equals(type))
                .containsExactly(new SearchIdentifierIndexState(type, "[{\"dni\":[\"x\"]}]", "0011223344556677"));
    }
}
