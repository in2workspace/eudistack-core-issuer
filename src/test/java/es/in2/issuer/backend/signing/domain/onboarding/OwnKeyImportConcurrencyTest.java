package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeKms;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeStore;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.RecordingArtifacts;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import es.in2.issuer.backend.signing.domain.spi.OnboardingArtifactsPort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Two runs of the same {@code import} must not overlap (security audit N-1): the second one must not be able to take
 * the key the first one has just imported for its own to clean up, and a run only cleans up an enabled key if it
 * imported it itself.
 */
class OwnKeyImportConcurrencyTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String CALLER = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final RecordingArtifacts artifacts = new RecordingArtifacts();
    private final OwnKeyTestPki.Leaf leaf = pki.validP256Leaf();
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private OwnKeyOnboarding onboarding;

    @BeforeEach
    void setUp() {
        store.tenants.put("cgcom", OnboardingFakes.activeTenant("cgcom", null));
        onboarding = new OwnKeyOnboarding(kms, store, () -> CALLER, Clock.fixed(NOW, ZoneOffset.UTC), () -> "op-1", 7);
        kms.publicKey = leaf.publicKeyDer();
    }

    @AfterEach
    void stopThreads() {
        executor.shutdownNow();
    }

    private PreparedOnboarding prepared() throws Exception {
        onboarding.prepare(new PrepareCommand("cgcom", OwnKeyCertificateValidatorTest.toPem(leaf.certificate()),
                OnboardingPolicy.nonProduction(), null, false, artifacts));
        kms.calls.clear();
        return artifacts.prepared;
    }

    private ImportCommand importOf(PreparedOnboarding prepared) {
        return new ImportCommand(prepared, new byte[] {1}, new byte[] {2}, OnboardingPolicy.nonProduction(), false,
                artifacts);
    }

    private void assertNoKeyWasDisabledOrDeleted() {
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion")
                || call.startsWith("deleteAlias"));
    }

    @Test
    void importKey_secondRunWhileTheFirstIsBetweenTheImportAndTheCommit_cannotDisableTheKeyTheFirstActivates()
            throws Exception {
        var prepared = prepared();
        CountDownLatch firstHasImported = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        AtomicBoolean firstCall = new AtomicBoolean(true);
        kms.duringGetPublicKey = () -> {
            if (firstCall.getAndSet(false)) {
                firstHasImported.countDown();
                await(releaseFirst);
            }
        };
        Future<?> first = executor.submit(() -> onboarding.importKey(importOf(prepared)));
        assertThat(firstHasImported.await(10, TimeUnit.SECONDS)).isTrue();
        int kmsCallsOfTheFirst = kms.calls.size();

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared)))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("another run is importing");

        assertThat(kms.calls).as("the second run made no call to KMS").hasSize(kmsCallsOfTheFirst);
        releaseFirst.countDown();
        first.get(10, TimeUnit.SECONDS);
        assertNoKeyWasDisabledOrDeleted();
        assertThat(kms.calls("importKeyMaterial")).hasSize(1);
        assertThat(store.committedOperations).anyMatch(operation -> operation.startsWith("activate:"));
        assertThat(store.lockedOperations).isEmpty();
    }

    @Test
    void importKey_afterTheFirstRunEnded_theLockIsFreeAgain() throws Exception {
        var prepared = prepared();

        onboarding.importKey(importOf(prepared));

        assertThat(store.lockedOperations).isEmpty();
    }

    @Test
    void importKey_failingRun_releasesTheLock() throws Exception {
        var prepared = prepared();
        kms.failures.put("importKeyMaterial", new IllegalStateException("KMS refuses"));

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).isInstanceOf(IllegalStateException.class);

        assertThat(store.lockedOperations).isEmpty();
    }

    @Test
    void importKey_dryRun_takesNoLock() throws Exception {
        var prepared = prepared();
        store.lockedOperations.add(prepared.operationId());

        onboarding.importKey(new ImportCommand(prepared, new byte[] {1}, new byte[] {2},
                OnboardingPolicy.nonProduction(), true, artifacts));

        assertThat(store.lockedOperations).containsExactly(prepared.operationId());
    }

    @Test
    void importKey_importFailsWhileTheKeyIsEnabledByAnotherRun_theKeyIsNotTouched() throws Exception {
        var prepared = prepared();
        // Something imported the material between the checks and the call of this run, which then fails.
        kms.beforeImportKeyMaterial = () -> kms.states.put(FakeKms.KEY_ARN, KeyState.ENABLED);
        kms.failures.put("importKeyMaterial", new IllegalStateException("the key already has material"));

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).isInstanceOf(IllegalStateException.class);

        assertNoKeyWasDisabledOrDeleted();
    }

    @Test
    void importKey_failureAfterThisRunImportedTheMaterial_disablesTheKeyItImported() throws Exception {
        var prepared = prepared();
        kms.failures.put("getPublicKey", new IllegalStateException("KMS unavailable"));

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).isInstanceOf(IllegalStateException.class);

        assertThat(kms.calls("disableKey")).hasSize(1);
        assertThat(kms.calls("scheduleKeyDeletion")).hasSize(1);
    }

    @Test
    void importKey_keyNotEnabledAfterTheCommit_failsAndTheCommitStands() throws Exception {
        var prepared = prepared();
        store.onTransactionStart = () -> kms.states.put(FakeKms.KEY_ARN, KeyState.DISABLED);

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared)))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("committed")
                .hasMessageContaining("DISABLED");

        assertThat(store.committedOperations).anyMatch(operation -> operation.startsWith("activate:"));
        assertNoKeyWasDisabledOrDeleted();
        assertThat(artifacts.imported).as("the state is consumed: the commit happened").isEqualTo(prepared);
    }

    @Test
    void importKey_commitThenFailureMarkingTheState_succeedsAndTellsTheCaller() throws Exception {
        var prepared = prepared();
        ImportCommand command = new ImportCommand(prepared, new byte[] {1}, new byte[] {2},
                OnboardingPolicy.nonProduction(), false, new OnboardingArtifactsPort() {
                    @Override
                    public void markImported(PreparedOnboarding p, Instant importedAt) {
                        throw new IllegalStateException("disk full");
                    }

                    @Override
                    public void markDiscarded(PreparedOnboarding p, Instant discardedAt) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public void write(PreparedOnboarding p, byte[] wrappingPublicKeyDer, byte[] importToken) {
                        throw new UnsupportedOperationException();
                    }
                });

        var result = onboarding.importKey(command);

        assertThat(result.stateMarkedAsConsumed()).isFalse();
        assertThat(store.committedOperations).anyMatch(operation -> operation.startsWith("activate:"));
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
