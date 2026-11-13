package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprint;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierIndexState;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore;
import lombok.RequiredArgsConstructor;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

/**
 * R2DBC adapter of {@link SearchIdentifierStore} on {@code issuance_search_identifier} and
 * {@code search_identifier_index_state} (V20). Tenant-scoped via {@code search_path}: the tenant must be in the
 * Reactor context before subscribing. The fingerprints are bound as bytes and never logged.
 */
@Repository
@RequiredArgsConstructor
public class R2dbcSearchIdentifierStore implements SearchIdentifierStore {

    private static final String ISSUANCE_ID = "issuanceId";
    private static final String TYPE = "type";

    private static final String INSERT_SQL = """
            INSERT INTO issuance_search_identifier (issuance_id, identifier_type, fingerprint)
            VALUES (:issuanceId, :type, :fingerprint)
            """;

    private static final String DELETE_OF_PROCESS_SQL =
            "DELETE FROM issuance_search_identifier WHERE issuance_id = :issuanceId";

    private static final String DELETE_OF_TYPE_SQL = """
            DELETE FROM issuance_search_identifier s
            USING issuance i
            WHERE s.issuance_id = i.issuance_id AND i.credential_type = :type
            """;

    private static final String PROCESSES_SQL = """
            SELECT issuance_id, credential_data_set FROM issuance
            WHERE credential_type = :type AND (CAST(:after AS uuid) IS NULL OR issuance_id > CAST(:after AS uuid))
            ORDER BY issuance_id
            LIMIT :limit
            """;

    private static final String SAVE_STATE_SQL = """
            INSERT INTO search_identifier_index_state
                (credential_configuration_id, search_identifiers, key_id, indexed_at)
            VALUES (:id, :identifiers, :keyId, now())
            ON CONFLICT (credential_configuration_id) DO UPDATE SET
                search_identifiers = EXCLUDED.search_identifiers,
                key_id = EXCLUDED.key_id,
                indexed_at = EXCLUDED.indexed_at
            """;

    private final DatabaseClient databaseClient;

    @Override
    public Mono<Void> insertAll(UUID issuanceId, List<SearchIdentifierFingerprint> fingerprints) {
        return Flux.fromIterable(fingerprints)
                .concatMap(fingerprint -> databaseClient.sql(INSERT_SQL)
                        .bind(ISSUANCE_ID, issuanceId)
                        .bind(TYPE, fingerprint.identifierType())
                        .bind("fingerprint", fingerprint.fingerprint())
                        .fetch()
                        .rowsUpdated())
                .then();
    }

    @Override
    public Mono<Void> replaceAll(UUID issuanceId, List<SearchIdentifierFingerprint> fingerprints) {
        return databaseClient.sql(DELETE_OF_PROCESS_SQL)
                .bind(ISSUANCE_ID, issuanceId)
                .fetch()
                .rowsUpdated()
                .then(insertAll(issuanceId, fingerprints));
    }

    @Override
    public Mono<Void> deleteAllOfType(String credentialType) {
        return databaseClient.sql(DELETE_OF_TYPE_SQL)
                .bind(TYPE, credentialType)
                .fetch()
                .rowsUpdated()
                .then();
    }

    @Override
    public Flux<StoredAttestation> processesOfType(String credentialType, UUID after, int limit) {
        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(PROCESSES_SQL)
                .bind(TYPE, credentialType)
                .bind("limit", limit);
        spec = after == null ? spec.bindNull("after", String.class) : spec.bind("after", after.toString());
        return spec.map((row, metadata) -> new StoredAttestation(
                        row.get("issuance_id", UUID.class), row.get("credential_data_set", String.class)))
                .all();
    }

    @Override
    public Flux<SearchIdentifierIndexState> findAllStates() {
        return databaseClient.sql(
                        "SELECT credential_configuration_id, search_identifiers, key_id FROM search_identifier_index_state")
                .map((row, metadata) -> new SearchIdentifierIndexState(
                        row.get("credential_configuration_id", String.class),
                        row.get("search_identifiers", String.class),
                        row.get("key_id", String.class)))
                .all();
    }

    @Override
    public Mono<Void> saveState(SearchIdentifierIndexState state) {
        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(SAVE_STATE_SQL)
                .bind("id", state.credentialConfigurationId())
                .bind("identifiers", state.searchIdentifiers());
        spec = state.keyId() == null ? spec.bindNull("keyId", String.class) : spec.bind("keyId", state.keyId());
        return spec.fetch().rowsUpdated().then();
    }
}
