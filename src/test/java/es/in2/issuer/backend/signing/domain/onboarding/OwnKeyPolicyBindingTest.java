package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeKms;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.FakeStore;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFakes.RecordingArtifacts;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.infrastructure.onboarding.BouncyCastleCertificateExtensions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** What {@code prepare} was accepted under binds {@code import}: it cannot run with a laxer or a different policy. */
class OwnKeyPolicyBindingTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String ORG = OwnKeyTestPki.ORGANIZATION_IDENTIFIER;

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final FakeKms kms = new FakeKms();
    private final FakeStore store = new FakeStore();
    private final RecordingArtifacts artifacts = new RecordingArtifacts();
    private final OwnKeyTestPki.Leaf leaf = pki.validP256Leaf();
    private OwnKeyOnboarding onboarding;

    @BeforeEach
    void setUp() {
        store.tenants.put("cgcom", OnboardingFakes.activeTenant("cgcom", null));
        onboarding = new OwnKeyOnboarding(kms, store, new BouncyCastleCertificateExtensions(),
                () -> "arn:caller", Clock.fixed(NOW, ZoneOffset.UTC),
                () -> "op-1", 7);
        kms.publicKey = leaf.publicKeyDer();
    }

    private PreparedOnboarding prepareWith(OnboardingPolicy policy) throws Exception {
        onboarding.prepare(new PrepareCommand("cgcom", OwnKeyCertificateValidatorTest.toPem(leaf.certificate()),
                policy, null, false, artifacts));
        kms.calls.clear();
        return artifacts.prepared;
    }

    private ImportCommand importWith(PreparedOnboarding prepared, OnboardingPolicy policy) {
        return new ImportCommand(prepared, new byte[] {1}, new byte[] {2}, policy, false, artifacts);
    }

    private OnboardingPolicy production() {
        return new OnboardingPolicy(true, pki.rootCertificate(), ORG);
    }

    private void assertTheKeyOfThePreparationWasLeftAlone() {
        assertThat(kms.calls).noneMatch(call -> call.startsWith("disableKey") || call.startsWith("scheduleKeyDeletion")
                || call.startsWith("importKeyMaterial"));
        assertThat(store.committedOperations).isEmpty();
    }

    @Test
    void prepare_recordsThePolicySummaryInTheState() throws Exception {
        var prepared = prepareWith(production());

        assertThat(prepared.policy().production()).isTrue();
        assertThat(prepared.policy().expectedOrganizationIdentifier()).isEqualTo(ORG);
        assertThat(prepared.policy().trustAnchorSha256()).hasSize(64);
    }

    @Test
    void importKey_withTheSameProductionPolicy_isAccepted() throws Exception {
        var prepared = prepareWith(production());

        assertThat(onboarding.importKey(importWith(prepared, production())).configurationId()).isNotNull();
    }

    @Test
    void importKey_withoutTheProductionChecksThatPrepareApplied_isRejectedAndTheKeyLeftAlone() throws Exception {
        var prepared = prepareWith(production());

        assertThatThrownBy(() -> onboarding.importKey(importWith(prepared, OnboardingPolicy.nonProduction())))
                .isInstanceOfSatisfying(OnboardingRejectedException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(RejectionReason.POLICY_DENIED);
                    assertThat(e.getMessage()).contains("laxer than or different");
                });

        assertTheKeyOfThePreparationWasLeftAlone();
        assertThat(store.eventsInOwnTransaction).hasSize(1);
    }

    @Test
    void importKey_withAnotherTrustAnchor_isRejectedAndTheKeyLeftAlone() throws Exception {
        var prepared = prepareWith(production());
        var other = new OnboardingPolicy(true, new OwnKeyTestPki().rootCertificate(), ORG);
        var command = importWith(prepared, other);

        assertThatThrownBy(() -> onboarding.importKey(command))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("trust anchor");

        assertTheKeyOfThePreparationWasLeftAlone();
    }

    @Test
    void importKey_withAnotherOrganizationIdentifier_isRejectedAndTheKeyLeftAlone() throws Exception {
        var prepared = prepareWith(production());
        var other = new OnboardingPolicy(true, pki.rootCertificate(), "VATES-Q9999999Z");
        var command = importWith(prepared, other);

        assertThatThrownBy(() -> onboarding.importKey(command))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("organizationIdentifier");

        assertTheKeyOfThePreparationWasLeftAlone();
    }

    @Test
    void importKey_aStricterPolicyThanPrepare_isAccepted() throws Exception {
        var prepared = prepareWith(OnboardingPolicy.nonProduction());

        assertThat(onboarding.importKey(importWith(prepared, production())).configurationId()).isNotNull();
    }

    private PreparedOnboarding withoutPolicy() throws Exception {
        var prepared = prepareWith(production());
        return new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt());
    }

    @Test
    void importKey_stateWithoutAPolicyAndWithoutTheProductionChecks_isTakenAsProductionAndRejected() throws Exception {
        var withoutPolicy = withoutPolicy();

        assertThatThrownBy(() -> onboarding.importKey(importWith(withoutPolicy, OnboardingPolicy.nonProduction())))
                .isInstanceOfSatisfying(OnboardingRejectedException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(RejectionReason.POLICY_DENIED);
                    assertThat(e.getMessage()).contains("no policy summary").contains("production checks");
                });

        assertTheKeyOfThePreparationWasLeftAlone();
        assertThat(store.eventsInOwnTransaction).hasSize(1);
    }

    @Test
    void importKey_stateWithoutAPolicyWithTheProductionChecks_isAccepted() throws Exception {
        var withoutPolicy = withoutPolicy();

        assertThat(onboarding.importKey(importWith(withoutPolicy, production())).configurationId()).isNotNull();
    }

    @Test
    void tenantIdUnknown_isNotAcceptedAsATenant() throws Exception {
        var command = new PrepareCommand("unknown", OwnKeyCertificateValidatorTest.toPem(leaf.certificate()),
                OnboardingPolicy.nonProduction(), null, false, artifacts);

        assertThatThrownBy(() -> onboarding.prepare(command)).isInstanceOf(OnboardingUsageException.class);
        assertThat(kms.calls).isEmpty();
    }

    @Test
    void keyArnOfTheFake_isTheOnePrepareCreated() throws Exception {
        assertThat(prepareWith(OnboardingPolicy.nonProduction()).keyArn()).isEqualTo(FakeKms.KEY_ARN);
    }
}
