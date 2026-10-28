package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeKms;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeStore;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.RecordingArtifacts;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
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
 * An {@code import} must never disable or schedule the deletion of a key that is not the new key its own preparation
 * created: not the active key of the tenant, not another tenant's, not one that any configuration references.
 */
class OwnKeyImportSafetyTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String CALLER = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";
    private static final String OTHER_KEY = "arn:aws:kms:eu-west-1:000000000000:key/ffffffff-0000-0000-0000-000000000000";

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final RecordingArtifacts artifacts = new RecordingArtifacts();
    private final OwnKeyTestPki.Leaf leaf = pki.validP256Leaf();
    private OwnKeyOnboarding onboarding;

    @BeforeEach
    void setUp() {
        store.tenants.put("cgcom", OnboardingFakes.activeTenant("cgcom", null));
        store.tenants.put("kpmg", OnboardingFakes.activeTenant("kpmg", null));
        onboarding = new OwnKeyOnboarding(kms, store, () -> CALLER, Clock.fixed(NOW, ZoneOffset.UTC), () -> "op-1", 7);
        kms.publicKey = leaf.publicKeyDer();
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

    private static PreparedOnboarding with(PreparedOnboarding p, String tenant, String keyArn) {
        return new PreparedOnboarding(p.operationId(), tenant, keyArn, p.alias(), p.certificateChain(), p.spkiSha256(),
                p.createdAt(), p.importTokenExpiresAt());
    }

    private void assertNoKeyWasTouched() {
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion")
                || call.startsWith("deleteAlias") || call.startsWith("importKeyMaterial"));
    }

    @Test
    void importKey_success_marksTheStateAsConsumed() throws Exception {
        var prepared = prepared();

        onboarding.importKey(importOf(prepared));

        assertThat(artifacts.imported).isEqualTo(prepared);
    }

    @Test
    void importKey_consumedState_isRefusedWithNoKmsCall() throws Exception {
        var prepared = prepared();
        var consumed = new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt(), false, null, NOW);

        assertThatThrownBy(() -> onboarding.importKey(importOf(consumed)))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("already imported");

        assertThat(kms.calls).isEmpty();
        assertThat(store.transactions).isZero();
    }

    @Test
    void importKey_sameStateImportedTwice_theActiveKeyIsNeverTouched() throws Exception {
        var prepared = prepared();
        onboarding.importKey(importOf(prepared));
        // The second run uses the very same state, as if marking it had failed: the key is now the active one.
        artifacts.current = null;
        store.active = new ActiveConfiguration(UUID.randomUUID(), SigningModality.OWN_KEY, FakeKms.KEY_ARN);
        store.activeKeyRefs.add(FakeKms.KEY_ARN);
        store.tenants.put("cgcom", new RegisteredTenant("cgcom", true, true, SigningModality.OWN_KEY,
                store.active.id(), FakeKms.KEY_ARN));
        store.reservations.put(new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(),
                new SpkiReservation("cgcom", store.active.id()));
        kms.calls.clear();
        int operationsBefore = store.committedOperations.size();

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared)))
                .isInstanceOf(OnboardingRejectedException.class);

        assertNoKeyWasTouched();
        assertThat(store.committedOperations).hasSize(operationsBefore);
    }

    @Test
    void importKey_stateNamingTheActiveKeyOfAnotherTenant_isRejectedAndThatKeyNeverTouched() throws Exception {
        var prepared = prepared();
        kms.states.put(OTHER_KEY, KeyState.ENABLED);
        kms.tags.clear();
        kms.tags.put("Tenant", "kpmg");
        kms.tags.put("operationId", "op-of-kpmg");
        store.activeKeyRefs.add(OTHER_KEY);

        assertThatThrownBy(() -> onboarding.importKey(importOf(with(prepared, "cgcom", OTHER_KEY))))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.POLICY_DENIED));

        assertNoKeyWasTouched();
        assertThat(store.eventsInOwnTransaction).hasSize(1);
    }

    @Test
    void importKey_stateWithAnotherTenantThanTheKeyWasTaggedFor_failsBeforeImporting() throws Exception {
        var prepared = prepared();

        assertThatThrownBy(() -> onboarding.importKey(importOf(with(prepared, "kpmg", prepared.keyArn()))))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("tags");

        assertNoKeyWasTouched();
        assertThat(store.committedOperations).isEmpty();
    }

    @Test
    void importKey_stateWhoseOperationIdIsNotTheKeys_failsBeforeImportingAndTouchesNothing() throws Exception {
        var prepared = prepared();
        kms.tags.put("operationId", "another-operation");

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared)))
                .isInstanceOf(OnboardingRejectedException.class);

        assertNoKeyWasTouched();
    }

    @Test
    void importKey_keyAlreadyHoldingMaterial_failsBeforeImportingAndTouchesNothing() throws Exception {
        var prepared = prepared();
        kms.states.put(prepared.keyArn(), KeyState.ENABLED);

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("material is imported");

        assertNoKeyWasTouched();
    }

    @Test
    void importKey_keyReferencedByAConfiguration_failsBeforeImportingAndTouchesNothing() throws Exception {
        var prepared = prepared();
        store.otherKeyRefs.add(prepared.keyArn());

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("references the key");

        assertNoKeyWasTouched();
    }

    @Test
    void importKey_dryRunWithAForeignKey_isRejectedWithoutRecordingAnything() throws Exception {
        var prepared = prepared();
        kms.tags.put("Tenant", "kpmg");

        assertThatThrownBy(() -> onboarding.importKey(new ImportCommand(prepared, null, new byte[0],
                OnboardingPolicy.nonProduction(), true, artifacts)))
                .isInstanceOf(OnboardingRejectedException.class);

        assertThat(store.eventsInOwnTransaction).isEmpty();
        assertNoKeyWasTouched();
    }

    @Test
    void importKey_repeatedRenewal_isRefusedBecauseTheStateWasConsumed() throws Exception {
        var activeId = UUID.randomUUID();
        store.tenants.put("cgcom", new RegisteredTenant("cgcom", true, true, SigningModality.OWN_KEY, activeId,
                FakeKms.KEY_ARN));
        store.reservations.put(new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(),
                new SpkiReservation("cgcom", activeId));
        store.active = new ActiveConfiguration(activeId, SigningModality.OWN_KEY, FakeKms.KEY_ARN);
        onboarding.prepare(new PrepareCommand("cgcom", OwnKeyCertificateValidatorTest.toPem(leaf.certificate()),
                OnboardingPolicy.nonProduction(), null, false, artifacts));
        var renewal = artifacts.prepared;
        onboarding.importKey(importOf(renewal));
        assertThat(artifacts.imported).isEqualTo(renewal);
        var consumed = new PreparedOnboarding(renewal.operationId(), renewal.tenant(), renewal.keyArn(), null,
                renewal.certificateChain(), renewal.spkiSha256(), renewal.createdAt(), null, true, null, NOW);
        kms.calls.clear();
        int events = store.committedEvents.size();

        assertThatThrownBy(() -> onboarding.importKey(importOf(consumed))).isInstanceOf(OnboardingFailedException.class);

        assertThat(kms.calls).isEmpty();
        assertThat(store.committedEvents).as("no spurious Replace").hasSize(events);
    }

    @Test
    void importKey_failureAfterTheImportWhileAConfigurationNowReferencesTheKey_doesNotTouchIt() throws Exception {
        var prepared = prepared();
        store.onTransactionStart = () -> store.activeKeyRefs.add(prepared.keyArn());
        store.failure = new OnboardingFailedException("database error");

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).hasMessage("database error");

        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion"));
    }

    @Test
    void importKey_compensation_alsoDeletesTheAliasOfTheKey() throws Exception {
        var prepared = prepared();
        store.failure = new OnboardingFailedException("database error");

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).hasMessage("database error");

        assertThat(kms.calls).contains("scheduleKeyDeletion:" + prepared.keyArn() + ":7",
                "deleteAlias:" + prepared.alias());
    }

    @Test
    void importKey_aliasThatDoesNotPointToTheKey_isLeftAlone() throws Exception {
        var prepared = prepared();
        kms.aliases.put(prepared.alias(), OTHER_KEY);
        store.failure = new OnboardingFailedException("database error");

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).hasMessage("database error");

        assertThat(kms.calls).contains("scheduleKeyDeletion:" + prepared.keyArn() + ":7")
                .noneMatch(call -> call.startsWith("deleteAlias"));
    }

    @Test
    void prepare_failureAfterCreatingTheKey_alsoDeletesItsAlias() {
        artifacts.failure = new OnboardingFailedException("disk full");

        assertThatThrownBy(() -> onboarding.prepare(new PrepareCommand("cgcom",
                pem(leaf), OnboardingPolicy.nonProduction(), null, false, artifacts))).hasMessage("disk full");

        assertThat(kms.calls).contains("scheduleKeyDeletion:" + FakeKms.KEY_ARN + ":7",
                "deleteAlias:alias/own-key-cgcom-op-1");
    }

    @Test
    void importKey_keyThatCannotBeCheckedInKms_isNotTouchedByTheCompensation() throws Exception {
        var prepared = prepared();
        store.failure = new OnboardingFailedException("database error");
        kms.failures.put("listTags", new OnboardingFailedException("KMS ListResourceTags failed"));
        // The first check (before the import) already fails: nothing is imported or destroyed.

        assertThatThrownBy(() -> onboarding.importKey(importOf(prepared))).isInstanceOf(OnboardingFailedException.class);

        assertNoKeyWasTouched();
    }

    private static String pem(OwnKeyTestPki.Leaf of) {
        try {
            return OwnKeyCertificateValidatorTest.toPem(of.certificate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
