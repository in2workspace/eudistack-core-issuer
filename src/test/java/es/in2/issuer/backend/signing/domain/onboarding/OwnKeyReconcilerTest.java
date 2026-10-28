package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeKms;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeStore;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.RegisteredTenant;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.WithdrawnOwnKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class OwnKeyReconcilerTest {

    private static final String CALLER = "arn:aws:iam::000000000000:role/operation";
    private static final Duration GRACE = Duration.ofSeconds(160);
    private static final String KEY_A = "arn:aws:kms:eu-west-1:000000000000:key/aaaa";
    private static final String KEY_B = "arn:aws:kms:eu-west-1:000000000000:key/bbbb";

    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final OwnKeyReconciler reconciler = new OwnKeyReconciler(kms, store, () -> CALLER,
            Clock.fixed(Instant.parse("2026-10-28T10:00:00Z"), ZoneOffset.UTC), 7);

    @BeforeEach
    void setUp() {
        store.tenants.put("cgcom", OnboardingFakes.activeTenant("cgcom", null));
    }

    private WithdrawnOwnKey withdrawn(String tenant, String keyArn) {
        var row = new WithdrawnOwnKey(UUID.randomUUID(), tenant, keyArn);
        store.withdrawn.add(row);
        return row;
    }

    @Test
    void reconcile_enabledKey_isDisabledScheduledForDeletionAndMarked() {
        var row = withdrawn("cgcom", KEY_A);

        var report = reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).containsExactly("describeKey:" + KEY_A, "disableKey:" + KEY_A,
                "scheduleKeyDeletion:" + KEY_A + ":7");
        assertThat(store.retired).containsExactly(row.id());
        assertThat(report.retired()).isEqualTo(1);
        assertThat(report.succeeded()).isTrue();
    }

    @Test
    void reconcile_disabledKey_isOnlyScheduledForDeletion() {
        withdrawn("cgcom", KEY_A);
        kms.states.put(KEY_A, KeyState.DISABLED);

        reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).containsExactly("describeKey:" + KEY_A, "scheduleKeyDeletion:" + KEY_A + ":7");
    }

    @Test
    void reconcile_keyAlreadyPendingDeletion_isOnlyMarked() {
        var row = withdrawn("cgcom", KEY_A);
        kms.states.put(KEY_A, KeyState.PENDING_DELETION);

        reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).containsExactly("describeKey:" + KEY_A);
        assertThat(store.retired).containsExactly(row.id());
    }

    @Test
    void reconcile_keyThatNoLongerExists_isOnlyMarked() {
        var row = withdrawn("cgcom", KEY_A);
        kms.states.put(KEY_A, KeyState.NOT_FOUND);

        reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).containsExactly("describeKey:" + KEY_A);
        assertThat(store.retired).containsExactly(row.id());
    }

    @Test
    void reconcile_runTwice_theSecondRunMakesNoKmsCall() {
        withdrawn("cgcom", KEY_A);
        reconciler.reconcile(GRACE, false);
        kms.calls.clear();

        var second = reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).isEmpty();
        assertThat(second.retired()).isZero();
    }

    @Test
    void reconcile_keyStillReferencedByAnActiveConfiguration_isNeverTouchedAndTheRowIsMarked() {
        var row = withdrawn("cgcom", KEY_A);
        store.activeKeyRefs.add(KEY_A);

        var report = reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).isEmpty();
        assertThat(store.retired).containsExactly(row.id());
        assertThat(report.succeeded()).isTrue();

        kms.calls.clear();
        reconciler.reconcile(GRACE, false);
        assertThat(kms.calls).as("not retried forever").isEmpty();
    }

    @Test
    void reconcile_dryRunOfAKeyStillInUse_makesNoKmsCall() {
        withdrawn("cgcom", KEY_A);
        store.activeKeyRefs.add(KEY_A);

        reconciler.reconcile(GRACE, true);

        assertThat(kms.calls).isEmpty();
    }

    @Test
    void reconcile_referenceCheckThatCannotRead_touchesNoKeyAndFails() {
        var row = withdrawn("cgcom", KEY_A);
        store.referenceCheckFailure = new OnboardingFailedException("cannot be shown to be unreferenced");

        var report = reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).isEmpty();
        assertThat(store.retired).doesNotContain(row.id());
        assertThat(report.succeeded()).isFalse();
    }

    @Test
    void reconcile_noWithdrawnRows_makesNoKmsCall() {
        var report = reconciler.reconcile(GRACE, false);

        assertThat(kms.calls).isEmpty();
        assertThat(report.retired()).isZero();
    }

    @Test
    void reconcile_failureOnOneKey_leavesItUnmarkedAndProcessesTheOthers() {
        var failing = withdrawn("cgcom", KEY_A);
        var fine = withdrawn("cgcom", KEY_B);
        kms.states.put(KEY_A, KeyState.OTHER);

        var report = reconciler.reconcile(GRACE, false);

        assertThat(store.retired).containsExactly(fine.id());
        assertThat(report.succeeded()).isFalse();
        assertThat(report.failures()).singleElement().asString().contains(failing.id().toString());
    }

    @Test
    void reconcile_scheduleDeletionFails_leavesTheRowForTheNextRun() {
        withdrawn("cgcom", KEY_A);
        kms.failures.put("scheduleKeyDeletion", new OnboardingFailedException("KMS ScheduleKeyDeletion failed"));

        var report = reconciler.reconcile(GRACE, false);

        assertThat(store.retired).isEmpty();
        assertThat(report.failures()).hasSize(1);
    }

    @Test
    void reconcile_failureOfOneTenant_doesNotStopTheOthers() {
        store.tenants.put("kpmg", OnboardingFakes.activeTenant("kpmg", null));
        var kpmgRow = withdrawn("kpmg", KEY_B);
        store.tenantsWithoutSchema.add("cgcom");

        var report = reconciler.reconcile(GRACE, false);

        assertThat(store.retired).containsExactly(kpmgRow.id());
        assertThat(report.failures()).singleElement().asString().startsWith("tenant cgcom");
    }

    @Test
    void reconcile_tenantWhoseSchemaIsNotProvisionedYet_isSkippedWithoutFailure() {
        store.tenants.put("ghost", new RegisteredTenant("ghost", true, false, null));
        var row = withdrawn("ghost", KEY_B);

        var report = reconciler.reconcile(GRACE, false);

        assertThat(report.succeeded()).isTrue();
        assertThat(store.retired).doesNotContain(row.id());
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void reconcile_dryRun_readsKeyStatesButWritesNothing() {
        withdrawn("cgcom", KEY_A);

        var report = reconciler.reconcile(GRACE, true);

        assertThat(kms.calls).containsExactly("describeKey:" + KEY_A);
        assertThat(store.retired).isEmpty();
        assertThat(store.transactions).isZero();
        assertThat(report.retired()).isEqualTo(1);
    }

    @Test
    void reconcile_retiredKey_leavesARetireSuccessEventWithTheCallerAndNoKeyReference() {
        var row = withdrawn("cgcom", KEY_A);

        reconciler.reconcile(GRACE, false);

        assertThat(store.committedEvents).singleElement().satisfies(event -> {
            assertThat(event.operation()).isEqualTo(SigningConfigurationChanged.Operation.RETIRE);
            assertThat(event.result()).isEqualTo(SigningConfigurationChanged.Result.SUCCESS);
            assertThat(event.tenant()).isEqualTo("cgcom");
            assertThat(event.actor()).isEqualTo(CALLER);
            assertThat(event.correlationId()).isEqualTo(row.id().toString());
            assertThat(event.toString()).doesNotContain(KEY_A);
        });
    }

    @Test
    void reconcile_keyStillReferencedByAnActiveConfiguration_leavesARetireDeniedEvent() {
        withdrawn("cgcom", KEY_A);
        store.activeKeyRefs.add(KEY_A);

        reconciler.reconcile(GRACE, false);

        assertThat(store.committedEvents).singleElement().satisfies(event -> {
            assertThat(event.result()).isEqualTo(SigningConfigurationChanged.Result.DENIED);
            assertThat(event.reason()).isEqualTo(RejectionReason.KEY_IN_USE);
        });
    }

    @Test
    void reconcile_failureOnAKey_recordsARetireFailureEventInATransactionOfItsOwn() {
        var failing = withdrawn("cgcom", KEY_A);
        kms.states.put(KEY_A, KeyState.OTHER);

        reconciler.reconcile(GRACE, false);

        assertThat(store.committedEvents).isEmpty();
        assertThat(store.eventsInOwnTransaction).singleElement().satisfies(event -> {
            assertThat(event.operation()).isEqualTo(SigningConfigurationChanged.Operation.RETIRE);
            assertThat(event.result()).isEqualTo(SigningConfigurationChanged.Result.FAILURE);
            assertThat(event.reason()).isEqualTo(RejectionReason.PROVIDER_UNAVAILABLE);
            assertThat(event.actor()).isEqualTo(CALLER);
            assertThat(event.correlationId()).isEqualTo(failing.id().toString());
        });
    }

    private OwnKeyReconciler reconcilerCountingIdentityCalls(AtomicInteger calls) {
        return new OwnKeyReconciler(kms, store, () -> {
            calls.incrementAndGet();
            return CALLER;
        }, Clock.fixed(Instant.parse("2026-10-28T10:00:00Z"), ZoneOffset.UTC), 7);
    }

    @Test
    void reconcile_nothingToRetire_doesNotAskForTheCallerIdentity() {
        AtomicInteger identityCalls = new AtomicInteger();

        var report = reconcilerCountingIdentityCalls(identityCalls).reconcile(GRACE, false);

        assertThat(report.retired()).isZero();
        assertThat(identityCalls).hasValue(0);
    }

    @Test
    void reconcile_severalRows_asksForTheCallerIdentityOnceAndOnlyWhenThereIsARow() {
        withdrawn("cgcom", KEY_A);
        withdrawn("cgcom", KEY_B);
        AtomicInteger identityCalls = new AtomicInteger();

        var report = reconcilerCountingIdentityCalls(identityCalls).reconcile(GRACE, false);

        assertThat(report.retired()).isEqualTo(2);
        assertThat(identityCalls).hasValue(1);
    }

    @Test
    void reconcile_identityThatCannotBeRead_retiresNothingAndFailsTheRow() {
        withdrawn("cgcom", KEY_A);
        var reconcilerWithoutIdentity = new OwnKeyReconciler(kms, store, () -> {
            throw new OnboardingFailedException("STS is down");
        }, Clock.fixed(Instant.parse("2026-10-28T10:00:00Z"), ZoneOffset.UTC), 7);

        var report = reconcilerWithoutIdentity.reconcile(GRACE, false);

        assertThat(report.succeeded()).isFalse();
        assertThat(kms.calls).as("no key is retired without knowing who did it").isEmpty();
    }

    @Test
    void reconcile_dryRun_recordsNoEvent() {
        withdrawn("cgcom", KEY_A);

        reconciler.reconcile(GRACE, true);

        assertThat(store.committedEvents).isEmpty();
        assertThat(store.eventsInOwnTransaction).isEmpty();
    }

    @Test
    void reconcile_keyStillReferencedByAnActiveConfiguration_marksTheRowButKeepsItsSpkiReservation() {
        var row = withdrawn("cgcom", KEY_A);
        store.reservations.put("ab".repeat(32), new OwnKeyStorePort.SpkiReservation("cgcom", row.id()));
        store.activeKeyRefs.add(KEY_A);

        reconciler.reconcile(GRACE, false);

        assertThat(store.committedOperations).containsExactly("markStillInUse:" + KEY_A);
        assertThat(store.retired).contains(row.id());
        assertThat(store.reservations).containsOnlyKeys("ab".repeat(32));
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion"));
    }

    @Test
    void reconcile_retiredKey_releasesTheSpkiReservationOfItsRow() {
        var row = withdrawn("cgcom", KEY_A);
        store.reservations.put("ab".repeat(32), new OwnKeyStorePort.SpkiReservation("cgcom", row.id()));
        store.reservations.put("cd".repeat(32), new OwnKeyStorePort.SpkiReservation("cgcom", UUID.randomUUID()));

        reconciler.reconcile(GRACE, false);

        assertThat(store.reservations).containsOnlyKeys("cd".repeat(32));
    }
}
