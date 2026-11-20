package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprint;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierIndexState;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

/**
 * The fingerprints of the search identifiers of the issuance processes, and what each catalog entry was indexed
 * with (EUD-267). Tenant-scoped through the Reactor context like every other repository.
 */
public interface SearchIdentifierStore {

    /**
     * Stores the fingerprints of a new process. Runs in the transaction that inserts the process.
     *
     * @param keyId {@link es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter#keyId}
     *              of the tenant key the fingerprints were computed with
     */
    Mono<Void> insertAll(UUID issuanceId, String keyId, List<SearchIdentifierFingerprint> fingerprints);

    /**
     * Replaces every fingerprint of a process with these ones, computed with the key {@code keyId} (none: the
     * process has no fingerprint left).
     */
    Mono<Void> replaceAll(UUID issuanceId, String keyId, List<SearchIdentifierFingerprint> fingerprints);

    /**
     * A page of the processes of a credential type with at least one fingerprint computed with another key than
     * {@code keyId}, by ascending id: those after {@code after} ({@code null} for the first page), at most
     * {@code limit}.
     */
    Flux<StoredAttestation> processesWithAnotherKey(String credentialType, String keyId, UUID after, int limit);

    /** Deletes the fingerprints of every process of a credential type. */
    Mono<Void> deleteAllOfType(String credentialType);

    /**
     * A page of the processes of a credential type, by ascending id: those after {@code after} ({@code null} for
     * the first page), at most {@code limit}.
     */
    Flux<StoredAttestation> processesOfType(String credentialType, UUID after, int limit);

    Flux<SearchIdentifierIndexState> findAllStates();

    Mono<Void> saveState(SearchIdentifierIndexState state);

    /**
     * The attestation data a process stores, from which its fingerprints are computed again.
     *
     * @param credentialDataSet the attestation as built, before signing; {@code null} if the process has none
     */
    record StoredAttestation(UUID issuanceId, String credentialDataSet) {
    }
}
