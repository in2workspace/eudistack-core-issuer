package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprint;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierIndexState;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore.StoredAttestation;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SearchIdentifierIndexerTest {

    private static final String TENANT = "cgcom";
    private static final String TYPE = "doctorid.sd.1";
    private static final byte[] KEY = "a-tenant-secret-key-of-32-bytes!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ROTATED_KEY = "the-rotated-tenant-key-32-bytes!".getBytes(StandardCharsets.UTF_8);
    private static final CatalogEntry.SearchIdentifier DNI =
            new CatalogEntry.SearchIdentifier("dni", ClaimPath.of("credentialSubject", "dni"));
    private static final CatalogEntry.SearchIdentifier COLEGIADO =
            new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("credentialSubject", "colegiado"));
    private static final String BOTH = "{\"credentialSubject\":{\"dni\":\"12345678Z\",\"colegiado\":\"28/12345\"}}";

    @Mock private CatalogEntryPort catalogEntryPort;
    @Mock private IssuancePort issuancePort;
    @Mock private SearchIdentifierStore store;
    @Mock private TenantSecretKeyPort tenantSecretKeyPort;
    @Mock private TransactionalOperator transactionalOperator;

    private SearchIdentifierIndexer indexer;

    @BeforeEach
    void setUp() {
        indexer = new SearchIdentifierIndexer(catalogEntryPort, issuancePort, store, tenantSecretKeyPort,
                transactionalOperator, new ObjectMapper());
        lenient().when(transactionalOperator.transactional(any(Mono.class))).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(store.saveState(any())).thenReturn(Mono.empty());
        lenient().when(store.replaceAll(any(), anyList())).thenReturn(Mono.empty());
        lenient().when(store.deleteAllOfType(anyString())).thenReturn(Mono.empty());
    }

    private static CatalogEntry entry(List<CatalogEntry.SearchIdentifier> identifiers) {
        return new CatalogEntry(TYPE, "https://schema", true, null, null, null, identifiers, 3, null, null);
    }

    private static Issuance issuance(String dataSet) {
        return Issuance.builder().issuanceId(UUID.randomUUID()).credentialType(TYPE).credentialDataSet(dataSet).build();
    }

    private <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static byte[] fingerprint(byte[] key, String value) {
        return SearchIdentifierFingerprinter.fingerprint(key, value).orElseThrow();
    }

    // ---- on issuance ------------------------------------------------------------------------------------------

    @Test
    void saveWithFingerprints_storesTheProcessAndAFingerprintPerIdentifier_inOneTransaction() {
        Issuance issuance = issuance(BOTH);
        when(catalogEntryPort.findByIdForShare(TYPE)).thenReturn(Mono.just(entry(List.of(DNI, COLEGIADO))));
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        when(issuancePort.insert(issuance)).thenReturn(Mono.just(issuance));
        when(store.insertAll(any(), anyList())).thenReturn(Mono.empty());

        StepVerifier.create(inTenant(indexer.saveWithFingerprints(issuance))).expectNext(issuance).verifyComplete();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<SearchIdentifierFingerprint>> stored = ArgumentCaptor.forClass(List.class);
        verify(store).insertAll(eq(issuance.getIssuanceId()), stored.capture());
        assertThat(stored.getValue()).containsExactly(
                new SearchIdentifierFingerprint("dni", fingerprint(KEY, "12345678Z")),
                new SearchIdentifierFingerprint("colegiado", fingerprint(KEY, "28/12345")));
        verify(transactionalOperator).transactional(any(Mono.class));
    }

    @Test
    void saveWithFingerprints_anAttestationWithoutTheData_storesNoFingerprintForIt() {
        Issuance issuance = issuance("{\"credentialSubject\":{\"dni\":\"12345678Z\"}}");
        when(catalogEntryPort.findByIdForShare(TYPE)).thenReturn(Mono.just(entry(List.of(DNI, COLEGIADO))));
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        when(issuancePort.insert(issuance)).thenReturn(Mono.just(issuance));
        when(store.insertAll(any(), anyList())).thenReturn(Mono.empty());

        StepVerifier.create(inTenant(indexer.saveWithFingerprints(issuance))).expectNextCount(1).verifyComplete();

        verify(store).insertAll(issuance.getIssuanceId(),
                List.of(new SearchIdentifierFingerprint("dni", fingerprint(KEY, "12345678Z"))));
    }

    @Test
    void saveWithFingerprints_anEntryWithoutIdentifiers_storesNoFingerprint_andNeedsNoKey() {
        Issuance issuance = issuance(BOTH);
        when(catalogEntryPort.findByIdForShare(TYPE)).thenReturn(Mono.just(entry(List.of())));
        when(issuancePort.insert(issuance)).thenReturn(Mono.just(issuance));

        StepVerifier.create(inTenant(indexer.saveWithFingerprints(issuance))).expectNext(issuance).verifyComplete();

        verify(tenantSecretKeyPort, never()).keyOf(anyString());
        verify(store, never()).insertAll(any(), anyList());
    }

    @Test
    void saveWithFingerprints_aTypeWithoutCatalogEntry_storesNoFingerprint() {
        Issuance issuance = issuance(BOTH);
        when(catalogEntryPort.findByIdForShare(TYPE)).thenReturn(Mono.empty());
        when(issuancePort.insert(issuance)).thenReturn(Mono.just(issuance));

        StepVerifier.create(inTenant(indexer.saveWithFingerprints(issuance))).expectNext(issuance).verifyComplete();

        verify(store, never()).insertAll(any(), anyList());
    }

    @Test
    void saveWithFingerprints_withoutTheTenantKey_writesNothing() {
        Issuance issuance = issuance(BOTH);
        when(catalogEntryPort.findByIdForShare(TYPE)).thenReturn(Mono.just(entry(List.of(DNI))));
        when(tenantSecretKeyPort.keyOf(TENANT))
                .thenReturn(Mono.error(new TenantSecretKeyUnavailableException("No secret key")));

        StepVerifier.create(inTenant(indexer.saveWithFingerprints(issuance)))
                .verifyError(TenantSecretKeyUnavailableException.class);

        verify(issuancePort, never()).insert(any());
        verify(store, never()).insertAll(any(), anyList());
    }

    @Test
    void saveWithFingerprints_whenAFingerprintCannotBeStored_failsTheWholeTransaction() {
        Issuance issuance = issuance(BOTH);
        when(catalogEntryPort.findByIdForShare(TYPE)).thenReturn(Mono.just(entry(List.of(DNI))));
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        when(issuancePort.insert(issuance)).thenReturn(Mono.just(issuance));
        when(store.insertAll(any(), anyList())).thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(inTenant(indexer.saveWithFingerprints(issuance)))
                .verifyErrorMessage("db down");

        // The insert of the process and of its fingerprints run inside the same transactional Mono.
        verify(transactionalOperator, times(1)).transactional(any(Mono.class));
    }

    @Test
    void saveWithFingerprints_withoutTenant_fails() {
        StepVerifier.create(indexer.saveWithFingerprints(issuance(BOTH)))
                .verifyError(TenantNotResolvedException.class);
    }

    // ---- in the background ------------------------------------------------------------------------------------

    private void catalog(CatalogEntry... entries) {
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(entries));
    }

    private void states(SearchIdentifierIndexState... states) {
        when(store.findAllStates()).thenReturn(Flux.just(states));
    }

    @Test
    void reindexTenant_anEntryNeverIndexed_fingerprintsItsProcesses_andRecordsWhatWithIt() {
        catalog(entry(List.of(DNI, COLEGIADO)));
        states();
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        when(store.processesOfType(eq(TYPE), isNull(), anyInt())).thenReturn(Flux.just(
                new StoredAttestation(first, BOTH),
                new StoredAttestation(second, "{\"credentialSubject\":{\"colegiado\":\"28/1\"}}")));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store).replaceAll(first, List.of(
                new SearchIdentifierFingerprint("dni", fingerprint(KEY, "12345678Z")),
                new SearchIdentifierFingerprint("colegiado", fingerprint(KEY, "28/12345"))));
        verify(store).replaceAll(second, List.of(new SearchIdentifierFingerprint("colegiado", fingerprint(KEY, "28/1"))));
        verify(store).saveState(new SearchIdentifierIndexState(TYPE,
                SearchIdentifierIndexer.signatureOf(List.of(DNI, COLEGIADO)), SearchIdentifierFingerprinter.keyId(KEY)));
    }

    @Test
    void reindexTenant_anEntryAlreadyIndexedWithItsIdentifiersAndKey_isLeftAlone() {
        catalog(entry(List.of(DNI)));
        states(new SearchIdentifierIndexState(TYPE, SearchIdentifierIndexer.signatureOf(List.of(DNI)),
                SearchIdentifierFingerprinter.keyId(KEY)));
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store, never()).processesOfType(anyString(), any(), anyInt());
        verify(store, never()).saveState(any());
    }

    @Test
    void reindexTenant_anIdentifierAdded_fingerprintsWhatWasAlreadyIssued() {
        // AC-10 of EUD-169: the entry had dni, and colegiado is added.
        catalog(entry(List.of(DNI, COLEGIADO)));
        states(new SearchIdentifierIndexState(TYPE, SearchIdentifierIndexer.signatureOf(List.of(DNI)),
                SearchIdentifierFingerprinter.keyId(KEY)));
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        UUID issued = UUID.randomUUID();
        when(store.processesOfType(eq(TYPE), isNull(), anyInt())).thenReturn(Flux.just(new StoredAttestation(issued, BOTH)));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<SearchIdentifierFingerprint>> stored = ArgumentCaptor.forClass(List.class);
        verify(store).replaceAll(eq(issued), stored.capture());
        assertThat(stored.getValue()).extracting(SearchIdentifierFingerprint::identifierType)
                .containsExactly("dni", "colegiado");
    }

    @Test
    void reindexTenant_aRotatedKey_fingerprintsEverythingAgainWithTheNewOne() {
        catalog(entry(List.of(DNI)));
        states(new SearchIdentifierIndexState(TYPE, SearchIdentifierIndexer.signatureOf(List.of(DNI)),
                SearchIdentifierFingerprinter.keyId(KEY)));
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(ROTATED_KEY));
        UUID issued = UUID.randomUUID();
        when(store.processesOfType(eq(TYPE), isNull(), anyInt())).thenReturn(Flux.just(new StoredAttestation(issued, BOTH)));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store).replaceAll(issued, List.of(new SearchIdentifierFingerprint("dni", fingerprint(ROTATED_KEY, "12345678Z"))));
        verify(store).saveState(new SearchIdentifierIndexState(TYPE, SearchIdentifierIndexer.signatureOf(List.of(DNI)),
                SearchIdentifierFingerprinter.keyId(ROTATED_KEY)));
    }

    @Test
    void reindexTenant_identifiersRemoved_deletesTheFingerprintsOfTheType_withoutReadingTheKey() {
        catalog(entry(List.of()));
        states(new SearchIdentifierIndexState(TYPE, SearchIdentifierIndexer.signatureOf(List.of(DNI)),
                SearchIdentifierFingerprinter.keyId(KEY)));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store).deleteAllOfType(TYPE);
        verify(store).saveState(new SearchIdentifierIndexState(TYPE, "[]", null));
        verify(tenantSecretKeyPort, never()).keyOf(anyString());
    }

    @Test
    void reindexTenant_anEntryWithoutIdentifiersAlreadyRecorded_isLeftAlone() {
        catalog(entry(List.of()));
        states(new SearchIdentifierIndexState(TYPE, "[]", null));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store, never()).deleteAllOfType(anyString());
        verify(store, never()).saveState(any());
    }

    @Test
    void reindexTenant_goesThroughEveryPage() {
        catalog(entry(List.of(DNI)));
        states();
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        List<StoredAttestation> firstPage = new ArrayList<>();
        IntStream.range(0, SearchIdentifierIndexer.PAGE_SIZE)
                .forEach(i -> firstPage.add(new StoredAttestation(UUID.randomUUID(), BOTH)));
        UUID lastOfFirstPage = firstPage.getLast().issuanceId();
        UUID onSecondPage = UUID.randomUUID();
        when(store.processesOfType(eq(TYPE), isNull(), anyInt())).thenReturn(Flux.fromIterable(firstPage));
        when(store.processesOfType(TYPE, lastOfFirstPage, SearchIdentifierIndexer.PAGE_SIZE))
                .thenReturn(Flux.just(new StoredAttestation(onSecondPage, BOTH)));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store, times(SearchIdentifierIndexer.PAGE_SIZE + 1)).replaceAll(any(), anyList());
        verify(store).replaceAll(eq(onSecondPage), anyList());
    }

    @Test
    void reindexTenant_aProcessWhoseDataIsNotAnAttestation_isSkipped_andTheOthersGoOn() {
        catalog(entry(List.of(DNI)));
        states();
        when(tenantSecretKeyPort.keyOf(TENANT)).thenReturn(Mono.just(KEY));
        UUID broken = UUID.randomUUID();
        UUID fine = UUID.randomUUID();
        when(store.processesOfType(eq(TYPE), isNull(), anyInt())).thenReturn(Flux.just(
                new StoredAttestation(broken, "not json"), new StoredAttestation(fine, BOTH)));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyComplete();

        verify(store, never()).replaceAll(eq(broken), anyList());
        verify(store).replaceAll(eq(fine), anyList());
        verify(store).saveState(any());
    }

    @Test
    void reindexTenant_withoutTheTenantKey_failsAndRecordsNothing_soTheNextRunTriesAgain() {
        catalog(entry(List.of(DNI)));
        states();
        when(tenantSecretKeyPort.keyOf(TENANT))
                .thenReturn(Mono.error(new TenantSecretKeyUnavailableException("No secret key")));

        StepVerifier.create(inTenant(indexer.reindexTenant())).verifyError(TenantSecretKeyUnavailableException.class);

        verify(store, never()).saveState(any());
    }

    @Test
    void reindexTenants_goesThroughEveryTenant_evenWhenOneFails() {
        when(catalogEntryPort.findAll()).thenReturn(Flux.error(new IllegalStateException("schema gone")))
                .thenReturn(Flux.just(entry(List.of())));
        when(store.findAllStates()).thenReturn(Flux.empty());

        StepVerifier.create(indexer.reindexTenants(List.of("broken", "sandbox"))).verifyComplete();

        verify(store).saveState(new SearchIdentifierIndexState(TYPE, "[]", null));
    }

    @Test
    void reindexInBackground_runsWithoutBeingWaitedFor() {
        catalog(entry(List.of()));
        states();

        indexer.reindexInBackground(TENANT);

        verify(store, timeout(Duration.ofSeconds(5).toMillis())).saveState(new SearchIdentifierIndexState(TYPE, "[]", null));
    }

    @Test
    void signatureOf_isCanonical_andEscapesWhatWouldBreakIt() {
        CatalogEntry.SearchIdentifier odd = new CatalogEntry.SearchIdentifier("a", ClaimPath.of("x\"y", "b\\c"));

        assertThat(SearchIdentifierIndexer.signatureOf(List.of())).isEqualTo("[]");
        assertThat(SearchIdentifierIndexer.signatureOf(List.of(DNI)))
                .isEqualTo("[{\"dni\":[\"credentialSubject\",\"dni\"]}]");
        assertThat(SearchIdentifierIndexer.signatureOf(List.of(odd))).isEqualTo("[{\"a\":[\"x\\\"y\",\"b\\\\c\"]}]");
        assertThat(SearchIdentifierIndexer.signatureOf(List.of(DNI, COLEGIADO)))
                .isNotEqualTo(SearchIdentifierIndexer.signatureOf(List.of(COLEGIADO, DNI)));
    }
}
