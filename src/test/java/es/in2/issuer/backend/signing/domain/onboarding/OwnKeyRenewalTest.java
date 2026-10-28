package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeKms;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeStore;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.RecordingArtifacts;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.ActiveConfiguration;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.RegisteredTenant;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.SpkiReservation;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A certificate renewal that keeps the key: the SPKI is reserved by the tenant's own active own-key row, so the
 * key material is already in that row's KMS key and nothing is created or imported.
 */
class OwnKeyRenewalTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String CALLER = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";
    private static final String TENANT = "cgcom";
    private static final UUID ACTIVE_ID = UUID.fromString("00000000-0000-0000-0000-0000000000bb");

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final RecordingArtifacts artifacts = new RecordingArtifacts();
    private final OwnKeyTestPki.Leaf leaf = pki.validP256Leaf();
    private OwnKeyOnboarding onboarding;

    @BeforeEach
    void setUp() {
        onboarding = new OwnKeyOnboarding(kms, store, () -> CALLER, Clock.fixed(NOW, ZoneOffset.UTC), () -> "op-1", 7);
        kms.publicKey = leaf.publicKeyDer();
        store.tenants.put(TENANT, new RegisteredTenant(TENANT, true, true, SigningModality.OWN_KEY, ACTIVE_ID,
                FakeKms.KEY_ARN));
        store.reservations.put(spkiHex(), new SpkiReservation(TENANT, ACTIVE_ID));
        store.active = new ActiveConfiguration(ACTIVE_ID, SigningModality.OWN_KEY, FakeKms.KEY_ARN);
    }

    private String spkiHex() {
        return new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex();
    }

    private PrepareCommand prepareCommand(boolean dryRun) {
        try {
            return new PrepareCommand(TENANT, OwnKeyCertificateValidatorTest.toPem(leaf.certificate()),
                    OnboardingPolicy.nonProduction(), null, dryRun, artifacts);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private PreparedOnboarding prepared() {
        onboarding.prepare(prepareCommand(false));
        kms.calls.clear();
        return artifacts.prepared;
    }

    private static ImportCommand importCommand(PreparedOnboarding prepared, boolean dryRun) {
        return new ImportCommand(prepared, null, new byte[0], OnboardingPolicy.nonProduction(), dryRun);
    }

    private void assertTheActiveKeyWasNeverTouched() {
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion")
                || call.startsWith("createKey") || call.startsWith("importKeyMaterial"));
    }

    @Test
    void prepare_certificateRenewingTheActiveKey_createsNothingInKmsAndLeavesARenewalState() {
        var result = onboarding.prepare(prepareCommand(false));

        assertThat(kms.calls).containsExactly("getPublicKey");
        assertThat(result.operation()).isEqualTo(Operation.REPLACE);
        assertThat(artifacts.prepared.renewal()).isTrue();
        assertThat(artifacts.prepared.keyArn()).isEqualTo(FakeKms.KEY_ARN);
        assertThat(artifacts.prepared.importTokenExpiresAt()).isNull();
        assertThat(artifacts.wrappingPublicKey).isNull();
        assertThat(artifacts.importToken).isNull();
    }

    @Test
    void prepare_dryRunOfARenewal_onlyReadsThePublicKey() {
        var result = onboarding.prepare(prepareCommand(true));

        assertThat(result.prepared()).isNull();
        assertThat(kms.calls).containsExactly("getPublicKey");
        assertThat(artifacts.prepared).isNull();
    }

    @Test
    void prepare_keyReservedByAnotherTenant_isStillKeyInUse() {
        store.reservations.put(spkiHex(), new SpkiReservation("kpmg", ACTIVE_ID));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void prepare_staleReservationOfTheSameTenantNotTiedToTheActiveRow_isKeyInUse() {
        store.reservations.put(spkiHex(), new SpkiReservation(TENANT, UUID.randomUUID()));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));
    }

    @Test
    void prepare_tenantWhoseActiveConfigurationIsQtsp_isKeyInUse() {
        store.tenants.put(TENANT, new RegisteredTenant(TENANT, true, true, SigningModality.QTSP, ACTIVE_ID, null));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));
    }

    @Test
    void prepare_certificateThatIsNotTheExistingKeys_isRejectedWithoutTouchingAnything() {
        kms.publicKey = pki.unrelatedPublicKeyDer();

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.INVALID_KEY));

        assertThat(kms.calls).containsExactly("getPublicKey");
        assertThat(artifacts.prepared).isNull();
        assertThat(store.eventsInOwnTransaction).singleElement()
                .satisfies(event -> assertThat(event.reason()).isEqualTo(RejectionReason.INVALID_KEY));
    }

    @Test
    void importKey_renewal_swapsTheRowsKeepingTheSameKeyAndImportsNothing() {
        var prepared = prepared();

        var result = onboarding.importKey(importCommand(prepared, false));

        assertThat(kms.calls).containsExactly("getPublicKey", "describeKey:" + FakeKms.KEY_ARN);
        assertThat(store.committedOperations).containsExactly("lockActive:cgcom", "withdraw:OWN_KEY:" + CALLER,
                "markHandled:" + FakeKms.KEY_ARN, "activate:" + FakeKms.KEY_ARN + ":" + CALLER, "reserve:cgcom");
        assertThat(store.committedEvents).singleElement().satisfies(event -> {
            assertThat(event.operation()).isEqualTo(Operation.REPLACE);
            assertThat(event.previousModality()).isEqualTo(SigningModality.OWN_KEY);
            assertThat(event.result()).isEqualTo(Result.SUCCESS);
        });
        assertThat(result.keyArn()).isEqualTo(FakeKms.KEY_ARN);
        assertThat(result.operation()).isEqualTo(Operation.REPLACE);
        assertThat(store.activated).singleElement()
                .satisfies(row -> assertThat(row.operationId()).isEqualTo("op-1"));
    }

    @Test
    void importKey_renewalStateReadBeforeAnotherRunMarkedIt_replacesTheConfigurationOnlyOnce() {
        var staleCopy = prepared();
        onboarding.importKey(new ImportCommand(staleCopy, null, new byte[0], OnboardingPolicy.nonProduction(), false,
                artifacts));
        kms.calls.clear();
        var command = new ImportCommand(staleCopy, null, new byte[0], OnboardingPolicy.nonProduction(), false,
                artifacts);

        assertThatThrownBy(() -> onboarding.importKey(command))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("already imported");

        assertThat(kms.calls).isEmpty();
        assertThat(store.committedEvents).singleElement()
                .satisfies(event -> assertThat(event.operation()).isEqualTo(Operation.REPLACE));
    }

    @Test
    void importKey_renewalDryRun_makesNoKmsCallAndNoTransaction() {
        var prepared = prepared();

        onboarding.importKey(importCommand(prepared, true));

        assertThat(kms.calls).isEmpty();
        assertThat(store.transactions).isZero();
    }

    @Test
    void importKey_renewalWhoseKeyIsNotTheCertificates_isRejectedAndTheActiveKeyIsNeverTouched() {
        var prepared = prepared();
        kms.publicKey = pki.unrelatedPublicKeyDer();

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.INVALID_KEY));

        assertThat(kms.calls).containsExactly("getPublicKey");
        assertTheActiveKeyWasNeverTouched();
        assertThat(store.transactions).isZero();
        assertThat(store.eventsInOwnTransaction).hasSize(1);
    }

    @Test
    void importKey_renewalWhoseDatabaseFails_neverDisablesTheActiveKey() {
        var prepared = prepared();
        store.failure = new OnboardingFailedException("database error");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false))).hasMessage("database error");

        assertTheActiveKeyWasNeverTouched();
        assertThat(store.committedOperations).isEmpty();
    }

    @Test
    void importKey_renewalThatFailsWithoutARejection_isAuditedAsAReplaceFailure() {
        var prepared = prepared();
        store.failure = new OnboardingFailedException("database error");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false))).hasMessage("database error");

        assertThat(store.eventsInOwnTransaction).singleElement().satisfies(event -> {
            assertThat(event.operation()).isEqualTo(Operation.REPLACE);
            assertThat(event.previousModality()).isEqualTo(SigningModality.OWN_KEY);
            assertThat(event.result()).isEqualTo(Result.FAILURE);
            assertThat(event.reason()).isEqualTo(RejectionReason.PROVIDER_UNAVAILABLE);
            assertThat(event.correlationId()).isEqualTo("op-1");
        });
    }

    @Test
    void importKey_renewalWhoseCommitOutcomeIsUnknown_leavesNoFailureEvent() {
        var prepared = prepared();
        store.failure = new CommitOutcomeUnknownException("the database did not confirm the commit", null);

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOf(CommitOutcomeUnknownException.class);

        assertThat(store.eventsInOwnTransaction).isEmpty();
    }

    @Test
    void importKey_renewalWhenTheActiveRowChangedMeanwhile_isRejectedAndTheKeyIsNeverTouched() {
        var prepared = prepared();
        store.active = new ActiveConfiguration(UUID.randomUUID(), SigningModality.OWN_KEY, "arn:another-key");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.POLICY_DENIED));

        assertTheActiveKeyWasNeverTouched();
        assertThat(store.committedOperations).isEmpty();
    }

    @Test
    void importKey_renewalStateWhoseTenantNoLongerHoldsTheKey_isRejectedAndTheKeyIsNeverTouched() {
        var prepared = prepared();
        store.reservations.clear();
        var command = importCommand(prepared, false);

        assertThatThrownBy(() -> onboarding.importKey(command))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("run prepare again");

        assertThat(kms.calls).isEmpty();
    }

    @Test
    void importKey_discardedState_isRefusedWithoutAnyKmsCall() {
        var prepared = prepared();
        var discarded = new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(), null,
                prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(), null, false, NOW);
        var command = importCommand(discarded, false);

        assertThatThrownBy(() -> onboarding.importKey(command))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("discarded");

        assertThat(kms.calls).isEmpty();
    }
}
