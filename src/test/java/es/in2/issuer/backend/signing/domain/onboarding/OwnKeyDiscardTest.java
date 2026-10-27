package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeKms;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeStore;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.RecordingArtifacts;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.DiscardCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.DiscardOutcome;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Giving up a preparation that was never imported. */
class OwnKeyDiscardTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String ARN = FakeKms.KEY_ARN;

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final RecordingArtifacts artifacts = new RecordingArtifacts();
    private OwnKeyOnboarding onboarding;
    private PreparedOnboarding prepared;

    @BeforeEach
    void setUp() throws Exception {
        store.tenants.put("cgcom", OnboardingFakes.activeTenant("cgcom", null));
        onboarding = new OwnKeyOnboarding(kms, store, () -> "arn:caller", Clock.fixed(NOW, ZoneOffset.UTC),
                () -> "op-1", 7);
        var leaf = pki.validP256Leaf();
        onboarding.prepare(new PrepareCommand("cgcom", OwnKeyCertificateValidatorTest.toPem(leaf.certificate()),
                OnboardingPolicy.nonProduction(), null, false, artifacts));
        prepared = artifacts.prepared;
        kms.calls.clear();
        kms.states.put(ARN, KeyState.PENDING_IMPORT);
        kms.tags.put("Tenant", "cgcom");
        kms.tags.put("operationId", "op-1");
    }

    private DiscardCommand command(boolean dryRun) {
        return new DiscardCommand(prepared, dryRun, artifacts);
    }

    private void assertNothingDestroyed() {
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion")
                || call.startsWith("deleteAlias"));
        assertThat(artifacts.discarded).isNull();
    }

    @Test
    void discard_unimportedPreparation_disablesSchedulesDeletionDeletesTheAliasAndMarksTheState() {
        var result = onboarding.discard(command(false));

        assertThat(result.outcome()).isEqualTo(DiscardOutcome.DISCARDED);
        assertThat(kms.calls).containsExactly("describeKey:" + ARN, "listTags:" + ARN, "disableKey:" + ARN,
                "scheduleKeyDeletion:" + ARN + ":7", "resolveKeyArn:" + prepared.alias(), "deleteAlias:" + prepared.alias());
        assertThat(artifacts.discarded).isEqualTo(prepared);
    }

    @Test
    void discard_dryRun_onlyChecks() {
        var result = onboarding.discard(command(true));

        assertThat(result.outcome()).isEqualTo(DiscardOutcome.WOULD_DISCARD);
        assertThat(kms.calls).containsExactly("describeKey:" + ARN, "listTags:" + ARN);
        assertNothingDestroyed();
    }

    @Test
    void discard_keyThatHasItsMaterialImported_isRefused() {
        kms.states.put(ARN, KeyState.ENABLED);

        assertThatThrownBy(() -> onboarding.discard(command(false)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("imported");

        assertNothingDestroyed();
    }

    @Test
    void discard_disabledKeyThatHadMaterial_isRefused() {
        kms.states.put(ARN, KeyState.DISABLED);

        assertThatThrownBy(() -> onboarding.discard(command(false))).isInstanceOf(OnboardingRejectedException.class);

        assertNothingDestroyed();
    }

    @Test
    void discard_keyWhoseOperationIdTagIsAnotherOnes_isRefused() {
        kms.tags.put("operationId", "op-other");

        assertThatThrownBy(() -> onboarding.discard(command(false)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("tags");

        assertNothingDestroyed();
    }

    @Test
    void discard_keyWhoseTenantTagIsAnotherTenants_isRefused() {
        kms.tags.put("Tenant", "kpmg");

        assertThatThrownBy(() -> onboarding.discard(command(false))).isInstanceOf(OnboardingRejectedException.class);

        assertNothingDestroyed();
    }

    @Test
    void discard_keyWithoutTags_isRefused() {
        kms.tags.clear();

        assertThatThrownBy(() -> onboarding.discard(command(false))).isInstanceOf(OnboardingRejectedException.class);

        assertNothingDestroyed();
    }

    @Test
    void discard_keyReferencedByASigningConfigurationOfAnyStatus_isRefused() {
        store.otherKeyRefs.add(ARN);

        assertThatThrownBy(() -> onboarding.discard(command(false)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("references the key");

        assertNothingDestroyed();
    }

    @Test
    void discard_keyReferencedByAnActiveConfiguration_isRefused() {
        store.activeKeyRefs.add(ARN);

        assertThatThrownBy(() -> onboarding.discard(command(false))).isInstanceOf(OnboardingRejectedException.class);

        assertNothingDestroyed();
    }

    @Test
    void discard_keyAlreadyPendingDeletion_onlyMarksTheState() {
        kms.states.put(ARN, KeyState.PENDING_DELETION);

        var result = onboarding.discard(command(false));

        assertThat(result.outcome()).isEqualTo(DiscardOutcome.ALREADY_DISCARDED);
        assertThat(kms.calls).containsExactly("describeKey:" + ARN);
        assertThat(artifacts.discarded).isEqualTo(prepared);
    }

    @Test
    void discard_keyThatNoLongerExists_onlyMarksTheState() {
        kms.states.put(ARN, KeyState.NOT_FOUND);

        assertThat(onboarding.discard(command(false)).outcome()).isEqualTo(DiscardOutcome.ALREADY_DISCARDED);
        assertThat(artifacts.discarded).isEqualTo(prepared);
    }

    @Test
    void discard_stateAlreadyDiscarded_makesNoKmsCall() {
        var already = new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt(), false, NOW);

        var result = onboarding.discard(new DiscardCommand(already, false, artifacts));

        assertThat(result.outcome()).isEqualTo(DiscardOutcome.ALREADY_DISCARDED);
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void discard_keyThatCannotBeDisabled_isStillScheduledForDeletion() {
        kms.failures.put("disableKey", new OnboardingFailedException("KMS DisableKey failed"));

        assertThat(onboarding.discard(command(false)).outcome()).isEqualTo(DiscardOutcome.DISCARDED);
        assertThat(kms.calls).contains("scheduleKeyDeletion:" + ARN + ":7");
    }

    @Test
    void discard_deletionThatCannotBeScheduled_failsAndLeavesTheStateUnmarked() {
        kms.failures.put("scheduleKeyDeletion", new OnboardingFailedException("KMS ScheduleKeyDeletion failed"));

        assertThatThrownBy(() -> onboarding.discard(command(false))).isInstanceOf(OnboardingFailedException.class);

        assertThat(artifacts.discarded).isNull();
        assertThat(kms.calls).noneMatch(call -> call.startsWith("deleteAlias"));
    }

    @Test
    void discard_aliasThatCannotBeDeleted_doesNotFailTheDiscard() {
        kms.failures.put("deleteAlias", new OnboardingFailedException("KMS DeleteAlias failed"));

        assertThat(onboarding.discard(command(false)).outcome()).isEqualTo(DiscardOutcome.DISCARDED);
        assertThat(artifacts.discarded).isEqualTo(prepared);
    }

    @Test
    void discard_renewalState_hasNothingToDiscard() {
        var renewal = new PreparedOnboarding("op-2", "cgcom", ARN, null, prepared.certificateChain(),
                prepared.spkiSha256(), NOW, null, true, null);

        assertThatThrownBy(() -> onboarding.discard(new DiscardCommand(renewal, false, artifacts)))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("nothing to discard");

        assertThat(kms.calls).isEmpty();
    }
}
