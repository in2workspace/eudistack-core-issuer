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
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OwnKeyOnboardingTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String CALLER = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";
    private static final String TENANT = "cgcom";
    private static final byte[] KEY_MATERIAL = {42, 43, 44, 45, 46};

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final RecordingArtifacts artifacts = new RecordingArtifacts();
    private final AtomicInteger identityCalls = new AtomicInteger();
    private OwnKeyOnboarding onboarding;
    private OwnKeyTestPki.Leaf leaf;

    @BeforeEach
    void setUp() {
        store.tenants.put(TENANT, OnboardingFakes.activeTenant(TENANT, null));
        onboarding = new OwnKeyOnboarding(kms, store, () -> {
            identityCalls.incrementAndGet();
            return CALLER;
        }, Clock.fixed(NOW, ZoneOffset.UTC), () -> "op-1", 7);
        leaf = pki.validP256Leaf();
        kms.publicKey = leaf.publicKeyDer();
    }

    private PrepareCommand prepareCommand(X509Certificate certificate, boolean dryRun) {
        try {
            return new PrepareCommand(TENANT, OwnKeyCertificateValidatorTest.toPem(certificate),
                    OnboardingPolicy.nonProduction(), null, dryRun, artifacts);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private PreparedOnboarding prepared() {
        onboarding.prepare(prepareCommand(leaf.certificate(), false));
        kms.calls.clear();
        return artifacts.prepared;
    }

    private ImportCommand importCommand(PreparedOnboarding prepared, boolean dryRun) {
        return new ImportCommand(prepared, artifacts.importToken, KEY_MATERIAL, OnboardingPolicy.nonProduction(), dryRun);
    }

    private void assertNothingDestroyed() {
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion")
                || call.startsWith("deleteAlias") || call.startsWith("importKeyMaterial"));
    }

    private void assertKeyDiscarded() {
        assertThat(kms.calls).contains("disableKey:" + FakeKms.KEY_ARN, "scheduleKeyDeletion:" + FakeKms.KEY_ARN + ":7");
    }

    @Test
    void prepare_dryRun_makesNoKmsCallNorWritesAnything() {
        var result = onboarding.prepare(prepareCommand(leaf.certificate(), true));

        assertThat(result.prepared()).isNull();
        assertThat(kms.calls).isEmpty();
        assertThat(artifacts.prepared).isNull();
        assertThat(store.eventsInOwnTransaction).isEmpty();
        assertThat(store.transactions).isZero();
        assertThat(identityCalls).hasValue(0);
    }

    @Test
    void prepare_dryRunWithRejectedCertificate_isRejectedWithoutRecordingAnything() {
        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(pki.rsaLeaf().certificate(), true)))
                .isInstanceOf(OnboardingRejectedException.class);

        assertThat(store.eventsInOwnTransaction).isEmpty();
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void prepare_validCertificate_createsTheTaggedKeyAndLeavesTheArtifacts() {
        var result = onboarding.prepare(prepareCommand(leaf.certificate(), false));

        assertThat(kms.calls).containsExactly("createKey:cgcom:op-1", "createAlias:alias/own-key-cgcom-op-1",
                "getParametersForImport");
        assertThat(artifacts.wrappingPublicKey).isEqualTo(kms.wrappingPublicKey);
        assertThat(artifacts.importToken).isEqualTo(kms.importToken);
        assertThat(result.prepared().keyArn()).isEqualTo(FakeKms.KEY_ARN);
        assertThat(result.prepared().operationId()).isEqualTo("op-1");
        assertThat(result.prepared().importTokenExpiresAt()).isEqualTo(kms.tokenValidTo);
        assertThat(result.operation()).isEqualTo(Operation.CREATE);
    }

    @Test
    void prepare_aliasGiven_usesIt() {
        onboarding.prepare(new PrepareCommand(TENANT, pemOf(leaf), OnboardingPolicy.nonProduction(),
                "alias/cgcom-signing", false, artifacts));

        assertThat(kms.calls).contains("createAlias:alias/cgcom-signing");
    }

    @Test
    void prepare_tenantWithAnActiveConfiguration_reportsAReplacement() {
        store.tenants.put(TENANT, OnboardingFakes.activeTenant(TENANT, SigningModality.QTSP));

        assertThat(onboarding.prepare(prepareCommand(leaf.certificate(), false)).operation()).isEqualTo(Operation.REPLACE);
    }

    @Test
    void prepare_rejectedCertificate_createsNothingInKmsAndRecordsTheRejection() {
        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(pki.rsaLeaf().certificate(), false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.INVALID_KEY));

        assertThat(kms.calls).isEmpty();
        assertThat(store.eventsInOwnTransaction).singleElement().satisfies(event -> {
            assertThat(event.result()).isEqualTo(Result.DENIED);
            assertThat(event.reason()).isEqualTo(RejectionReason.INVALID_KEY);
            assertThat(event.tenant()).isEqualTo(TENANT);
            assertThat(event.newModality()).isEqualTo(SigningModality.OWN_KEY);
            assertThat(event.actor()).isEqualTo(CALLER);
            assertThat(event.duration()).isNotNull();
        });
    }

    @Test
    void prepare_tenantNotInTheRegistry_isRejectedAsPolicyDenied() {
        store.tenants.clear();

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(RejectionReason.POLICY_DENIED);
                    assertThat(e.getMessage()).contains("not in the tenant registry");
                });
        assertThat(kms.calls).isEmpty();
        assertThat(store.eventsInOwnTransaction).as("audited with the tenant as given").singleElement()
                .satisfies(event -> {
                    assertThat(event.tenant()).isEqualTo(TENANT);
                    assertThat(event.result()).isEqualTo(Result.DENIED);
                    assertThat(event.reason()).isEqualTo(RejectionReason.POLICY_DENIED);
                });
    }

    @Test
    void prepare_inactiveTenant_isRejectedAsPolicyDenied() {
        store.tenants.put(TENANT, new RegisteredTenant(
                TENANT, false, true, null));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getMessage()).contains("not active"));
        assertThat(store.eventsInOwnTransaction).as("audited like any rejection").singleElement()
                .satisfies(event -> assertThat(event.reason()).isEqualTo(RejectionReason.POLICY_DENIED));
    }

    @Test
    void prepare_tenantWithoutIssuerSchema_isRejectedAsPolicyDenied() {
        store.tenants.put(TENANT, new RegisteredTenant(
                TENANT, true, false, null));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getMessage()).contains("schema"));
    }

    @Test
    void prepare_keyAlreadyReservedByAnotherTenant_isRejectedAsKeyInUse() {
        store.reserve(new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(), "kpmg");

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE);
                    assertThat(e.getMessage()).contains("kpmg");
                });
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void prepare_keyAlreadyReservedByTheSameTenant_isRejectedToo() {
        store.reserve(new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(), TENANT);

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));
    }

    @Test
    void prepare_invalidTenantId_isAUsageError() {
        var command = new PrepareCommand("Cg com;", pemOf(leaf), OnboardingPolicy.nonProduction(), null, false, artifacts);

        assertThatThrownBy(() -> onboarding.prepare(command)).isInstanceOf(OnboardingUsageException.class);
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void prepare_failureAfterCreateKey_schedulesTheDeletionOfTheNewKey() {
        artifacts.failure = new OnboardingFailedException("disk full");

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .hasMessage("disk full");

        assertKeyDiscarded();
    }

    @Test
    void prepare_failureAtGetParametersForImport_schedulesTheDeletionOfTheNewKey() {
        kms.failures.put("getParametersForImport", new OnboardingFailedException("KMS GetParametersForImport failed"));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .isInstanceOf(OnboardingFailedException.class);

        assertKeyDiscarded();
    }

    @Test
    void prepare_keyThatCannotBeDisabled_isStillScheduledForDeletion() {
        artifacts.failure = new OnboardingFailedException("disk full");
        kms.failures.put("disableKey", new OnboardingFailedException("KMS DisableKey failed"));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .hasMessage("disk full");

        assertThat(kms.calls).contains("scheduleKeyDeletion:" + FakeKms.KEY_ARN + ":7");
    }

    @Test
    void prepare_deletionThatCannotBeScheduled_keepsTheOriginalErrorAndAddsTheOther() {
        artifacts.failure = new OnboardingFailedException("disk full");
        kms.failures.put("scheduleKeyDeletion", new OnboardingFailedException("KMS ScheduleKeyDeletion failed"));

        assertThatThrownBy(() -> onboarding.prepare(prepareCommand(leaf.certificate(), false)))
                .hasMessage("disk full")
                .hasSuppressedException(new OnboardingFailedException("KMS ScheduleKeyDeletion failed"));
    }

    @Test
    void importKey_dryRun_makesNoKmsCallAndNoTransaction() {
        var prepared = prepared();

        var result = onboarding.importKey(importCommand(prepared, true));

        assertThat(result.configurationId()).isNull();
        assertThat(kms.calls).as("reads only").allMatch(call -> call.startsWith("describeKey") || call.startsWith("listTags"));
        assertThat(store.transactions).isZero();
        assertThat(store.eventsInOwnTransaction).isEmpty();
    }

    @Test
    void importKey_validState_importsComparesThePublicKeyAndActivatesInOneTransaction() {
        var prepared = prepared();

        var result = onboarding.importKey(importCommand(prepared, false));

        assertThat(kms.calls).containsExactly("describeKey:" + FakeKms.KEY_ARN, "listTags:" + FakeKms.KEY_ARN,
                "importKeyMaterial", "getPublicKey", "describeKey:" + FakeKms.KEY_ARN);
        assertThat(store.transactions).isEqualTo(1);
        assertThat(store.committedOperations).containsExactly("lockActive:cgcom",
                "activate:" + FakeKms.KEY_ARN + ":" + CALLER, "reserve:cgcom");
        assertThat(store.committedEvents).singleElement().satisfies(event -> {
            assertThat(event.operation()).isEqualTo(Operation.CREATE);
            assertThat(event.result()).isEqualTo(Result.SUCCESS);
            assertThat(event.previousModality()).isNull();
            assertThat(event.actor()).isEqualTo(CALLER);
            assertThat(event.correlationId()).isEqualTo("op-1");
        });
        assertThat(result.configurationId()).isEqualTo(UUID.fromString("00000000-0000-0000-0000-0000000000aa"));
    }

    @Test
    void importKey_replacingAnActiveConfiguration_withdrawsItInTheSameTransaction() {
        var prepared = prepared();
        store.active = new ActiveConfiguration(UUID.randomUUID(), SigningModality.QTSP);

        var result = onboarding.importKey(importCommand(prepared, false));

        assertThat(store.committedOperations).containsExactly("lockActive:cgcom", "withdraw:QTSP:" + CALLER,
                "activate:" + FakeKms.KEY_ARN + ":" + CALLER, "reserve:cgcom");
        assertThat(store.committedEvents).singleElement().satisfies(event -> {
            assertThat(event.operation()).isEqualTo(Operation.REPLACE);
            assertThat(event.previousModality()).isEqualTo(SigningModality.QTSP);
        });
        assertThat(result.operation()).isEqualTo(Operation.CREATE);
    }

    @Test
    void importKey_publicKeyOfTheKeyIsNotTheCertificates_isRejectedAndTheKeyDiscarded() {
        var prepared = prepared();
        kms.publicKey = pki.unrelatedPublicKeyDer();

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(RejectionReason.INVALID_KEY);
                    assertThat(e.getMessage()).contains("public key");
                });

        assertKeyDiscarded();
        assertThat(store.transactions).isZero();
        assertThat(store.committedOperations).isEmpty();
        assertThat(store.eventsInOwnTransaction).singleElement().satisfies(event -> {
            assertThat(event.result()).isEqualTo(Result.DENIED);
            assertThat(event.reason()).isEqualTo(RejectionReason.INVALID_KEY);
        });
    }

    @Test
    void importKey_databaseFailureAfterTheImport_discardsTheKeyAndLeavesTheDatabaseUnchanged() {
        var prepared = prepared();
        store.failure = new OnboardingFailedException("database error");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .hasMessage("database error");

        assertThat(kms.calls).contains("importKeyMaterial", "getPublicKey");
        assertKeyDiscarded();
        assertThat(store.committedOperations).isEmpty();
        assertThat(store.committedEvents).isEmpty();
    }

    @Test
    void importKey_commitWhoseOutcomeIsUnknown_doesNotDisableTheKey() {
        var prepared = prepared();
        store.failure = new CommitOutcomeUnknownException("the database did not confirm the commit", null);

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOf(CommitOutcomeUnknownException.class);

        assertThat(kms.calls).doesNotContain("disableKey:" + FakeKms.KEY_ARN)
                .noneMatch(call -> call.startsWith("scheduleKeyDeletion"));
    }

    @Test
    void importKey_keyReservedByAnotherOnboardingInTheMeantime_isRejectedAtTheReservationAndTheKeyDiscarded() {
        var prepared = prepared();
        // The validation made before the import sees nothing: the other onboarding commits after it.
        store.onTransactionStart = () -> store.reserve(
                new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(), "kpmg");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));

        assertKeyDiscarded();
        assertThat(store.committedOperations).isEmpty();
        assertThat(store.eventsInOwnTransaction).singleElement()
                .satisfies(event -> assertThat(event.reason()).isEqualTo(RejectionReason.KEY_IN_USE));
    }

    @Test
    void importKey_keyReservedAfterPrepare_isRejectedBeforeAnythingIsImportedAndTheKeyDiscarded() {
        var prepared = prepared();
        store.reserve(new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(), "kpmg");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));

        assertThat(kms.calls).doesNotContain("importKeyMaterial");
        assertKeyDiscarded();
        assertThat(store.eventsInOwnTransaction).singleElement()
                .satisfies(event -> assertThat(event.reason()).isEqualTo(RejectionReason.KEY_IN_USE));
    }

    @Test
    void importKey_tenantChangedAfterPrepare_isRejectedAsPolicyDenied() {
        var prepared = prepared();
        store.tenants.put(TENANT, new RegisteredTenant(
                TENANT, false, true, null));

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.POLICY_DENIED));
        assertKeyDiscarded();
        assertThat(store.eventsInOwnTransaction).hasSize(1);
    }

    @Test
    void importKey_certificateExpiredAfterPrepare_isRejected() {
        var prepared = prepared();
        var later = new OwnKeyOnboarding(kms, store, () -> CALLER,
                Clock.fixed(Instant.parse("2100-01-01T00:00:00Z"), ZoneOffset.UTC), () -> "op-2", 7);

        assertThatThrownBy(() -> later.importKey(importCommand(prepared, false)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("the certificate is not valid now");
        assertKeyDiscarded();
    }

    @Test
    void importKey_keyThatWaitsForItsMaterial_isScheduledForDeletionEvenIfItCannotBeDisabled() {
        var prepared = prepared();
        store.reserve(new ValidatedOwnKeyCertificate(List.of(leaf.certificate())).spkiSha256Hex(), "kpmg");
        kms.failures.put("disableKey", new OnboardingFailedException("KMS DisableKey failed (KMSInvalidStateException)"));

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOf(OnboardingRejectedException.class);

        assertThat(kms.calls).contains("scheduleKeyDeletion:" + FakeKms.KEY_ARN + ":7");
    }

    @Test
    void importKey_expiredImportToken_failsAndDiscardsTheKey() {
        var prepared = prepared();
        var later = new OwnKeyOnboarding(kms, store, () -> CALLER, Clock.fixed(kms.tokenValidTo, ZoneOffset.UTC),
                () -> "op-2", 7);

        assertThatThrownBy(() -> later.importKey(importCommand(prepared, false)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("run prepare again");
        assertKeyDiscarded();
        assertThat(store.eventsInOwnTransaction).as("the rejection is audited").hasSize(1);
    }

    @Test
    void importKey_stateThatDoesNotMatchItsChain_failsWithoutTouchingTheKey() {
        var prepared = prepared();
        var tampered = new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                prepared.alias(), prepared.certificateChain(), "00".repeat(32), prepared.createdAt(),
                prepared.importTokenExpiresAt(), false, null, null, prepared.policy());

        assertThatThrownBy(() -> onboarding.importKey(importCommand(tampered, false)))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("does not match");

        assertNothingDestroyed();
    }

    @Test
    void importKey_kmsRefusesTheKeyMaterial_isRejectedRecordedAndTheKeyDiscarded() {
        var prepared = prepared();
        kms.failures.put("importKeyMaterial",
                new OnboardingRejectedException(RejectionReason.INVALID_KEY, "KMS refused the key material"));

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOf(OnboardingRejectedException.class);

        assertKeyDiscarded();
        assertThat(store.eventsInOwnTransaction).singleElement()
                .satisfies(event -> assertThat(event.reason()).isEqualTo(RejectionReason.INVALID_KEY));
    }

    @Test
    void importKey_rejectionThatCannotBeRecorded_stillEndsAsARejection() {
        var prepared = prepared();
        kms.publicKey = pki.unrelatedPublicKeyDer();
        store.failureRecordingEvent = new OnboardingFailedException("database down");

        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasSuppressedException(new OnboardingFailedException("database down"));
    }

    @Test
    void events_neverCarryTheKeyMaterialTheTokenOrTheKeyReference() {
        var prepared = prepared();
        store.active = new ActiveConfiguration(UUID.randomUUID(), SigningModality.OWN_KEY);
        onboarding.importKey(importCommand(prepared, false));
        kms.publicKey = pki.unrelatedPublicKeyDer();
        assertThatThrownBy(() -> onboarding.importKey(importCommand(prepared, false)))
                .isInstanceOf(OnboardingRejectedException.class);

        List<String> events = new ArrayList<>();
        store.committedEvents.forEach(event -> events.add(event.toString()));
        store.eventsInOwnTransaction.forEach(event -> events.add(event.toString()));

        assertThat(events).hasSize(2).allSatisfy(event -> {
            assertThat(event).doesNotContain(Base64.getEncoder().encodeToString(KEY_MATERIAL));
            assertThat(event).doesNotContain(Base64.getEncoder().encodeToString(kms.importToken));
            assertThat(event).doesNotContain(HexFormat.of().formatHex(KEY_MATERIAL));
            assertThat(event).doesNotContain("kms:").doesNotContain("key/");
        });
    }

    private String pemOf(OwnKeyTestPki.Leaf of) {
        try {
            return OwnKeyCertificateValidatorTest.toPem(of.certificate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
