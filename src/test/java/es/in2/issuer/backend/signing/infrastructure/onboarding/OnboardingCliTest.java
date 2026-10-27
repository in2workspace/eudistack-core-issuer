package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.DiscardCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.DiscardOutcome;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.DiscardResult;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportResult;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareResult;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler.ReconcileReport;
import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OnboardingCliTest {

    private static final String PASSWORD = "s3cr3t-db-password";

    private final OwnKeyOnboarding onboarding = mock(OwnKeyOnboarding.class);
    private final OwnKeyReconciler reconciler = mock(OwnKeyReconciler.class);
    private final AtomicReference<OnboardingSettings> openedWith = new AtomicReference<>();
    private final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    private final Map<String, String> env = new HashMap<>();
    private OnboardingCli cli;

    @TempDir
    Path directory;

    @BeforeEach
    void setUp() {
        env.put("SPRING_FLYWAY_URL", "jdbc:postgresql://db:5432/issuer");
        env.put("SPRING_R2DBC_USERNAME", "operator");
        env.put("SPRING_R2DBC_PASSWORD", PASSWORD);
        cli = new OnboardingCli(settings -> {
            openedWith.set(settings);
            return new OnboardingCli.Services() {
                @Override
                public OwnKeyOnboarding onboarding() {
                    return onboarding;
                }

                @Override
                public OwnKeyReconciler reconciler() {
                    return reconciler;
                }

                @Override
                public void close() {
                    // Nothing to release: the collaborators are mocks.
                }
            };
        }, new PrintStream(stdout, true, StandardCharsets.UTF_8), new PrintStream(stderr, true, StandardCharsets.UTF_8));
    }

    private int run(String... args) {
        return cli.run(args, env);
    }

    private String out() {
        return stdout.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return stderr.toString(StandardCharsets.UTF_8);
    }

    private Path chainFile() throws Exception {
        var certificate = new OwnKeyTestPki().validP256Leaf().certificate();
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        return Files.writeString(directory.resolve("chain.pem"), pem);
    }

    private static PreparedOnboarding prepared() {
        return new PreparedOnboarding("op-1", "cgcom", "arn:aws:kms:eu-west-1:000000000000:key/abc",
                "alias/own-key-cgcom-op-1", List.of("AAAA"), "ab".repeat(32), Instant.parse("2026-10-27T12:00:00Z"),
                Instant.parse("2026-10-28T12:00:00Z"));
    }

    @Test
    void run_help_printsTheUsageAndTheExitCodes() {
        assertThat(run("--help")).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(out()).contains("prepare", "import", "reconcile", "--dry-run", "Exit codes");
    }

    @Test
    void run_helpAfterTheCommand_printsTheUsage() {
        assertThat(run("prepare", "--help")).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(out()).contains("Exit codes");
        verifyNoInteractions(onboarding);
    }

    @Test
    void run_noArguments_isAUsageError() {
        assertThat(run()).isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_unknownCommand_isAUsageError() {
        assertThat(run("withdraw")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("unknown command 'withdraw'");
    }

    @Test
    void run_optionOfAnotherCommand_isAUsageError() {
        assertThat(run("reconcile", "--tenant", "cgcom")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("unknown option --tenant");
    }

    @Test
    void run_missingRequiredOption_isAUsageErrorNamingTheEnvironmentVariable() throws Exception {
        assertThat(run("prepare", "--cert-chain", chainFile().toString(), "--out-dir", directory.toString()))
                .isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--tenant", "OWN_KEY_TENANT");
    }

    @Test
    void run_missingDatabasePassword_isAUsageError() throws Exception {
        env.remove("SPRING_R2DBC_PASSWORD");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("SPRING_R2DBC_PASSWORD");
    }

    @Test
    void run_productionWithoutTrustAnchor_isAUsageError() throws Exception {
        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--production", "--expected-org-id", "VATES-Q0000000X"))
                .isEqualTo(OnboardingCli.EXIT_USAGE);

        verifyNoInteractions(onboarding);
    }

    @Test
    void run_prepare_buildsTheCommandFromTheArgumentsAndPrintsTheResult() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--alias", "alias/cgcom", "--kms-endpoint", "http://localhost:4566",
                "--kms-region", "eu-west-1");

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<PrepareCommand> command = ArgumentCaptor.forClass(PrepareCommand.class);
        verify(onboarding).prepare(command.capture());
        assertThat(command.getValue().tenant()).isEqualTo("cgcom");
        assertThat(command.getValue().alias()).isEqualTo("alias/cgcom");
        assertThat(command.getValue().dryRun()).isFalse();
        assertThat(command.getValue().policy().production()).isFalse();
        assertThat(command.getValue().chainPem()).contains("BEGIN CERTIFICATE");
        assertThat(openedWith.get().kmsEndpoint()).hasToString("http://localhost:4566");
        assertThat(openedWith.get().kmsRegion()).isEqualTo("eu-west-1");
        assertThat(out()).contains("op-1", "arn:aws:kms:eu-west-1:000000000000:key/abc", "state.json");
    }

    @Test
    void run_prepareWithParametersFromTheEnvironment_worksTheSame() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));
        env.put("OWN_KEY_TENANT", "cgcom");
        env.put("OWN_KEY_CERT_CHAIN", chainFile().toString());
        env.put("OWN_KEY_OUT_DIR", directory.toString());
        env.put("ISSUER_SIGNING_KMS_REGION", "eu-west-1");

        assertThat(run("prepare")).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(openedWith.get().kmsRegion()).isEqualTo("eu-west-1");
    }

    @Test
    void run_regionFromAwsRegion_whenTheIssuerVariableIsNotSet() {
        env.put("AWS_REGION", "eu-south-2");

        run("reconcile");

        assertThat(openedWith.get().kmsRegion()).isEqualTo("eu-south-2");
    }

    @Test
    void run_prepareDryRun_needsNoOutputDirectory() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(null, Operation.CREATE, "ab".repeat(32)));

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--dry-run");

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<PrepareCommand> command = ArgumentCaptor.forClass(PrepareCommand.class);
        verify(onboarding).prepare(command.capture());
        assertThat(command.getValue().dryRun()).isTrue();
        assertThat(out()).contains("dry run");
    }

    @Test
    void run_rejectedOnboarding_exitsWithTwoAndTheReasonOnStderr() throws Exception {
        when(onboarding.prepare(any())).thenThrow(
                new OnboardingRejectedException(RejectionReason.INVALID_KEY, "the certificate key is not an EC P-256 key"));

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(err()).contains("REJECTED: the certificate key is not an EC P-256 key");
    }

    @Test
    void run_anyOtherFailure_exitsWithOne() throws Exception {
        when(onboarding.prepare(any())).thenThrow(new OnboardingFailedException("KMS CreateKey failed (AccessDenied)"));

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_ERROR);
        assertThat(err()).contains("ERROR: KMS CreateKey failed (AccessDenied)");
    }

    @Test
    void run_unexpectedException_exitsWithOne() throws Exception {
        when(onboarding.prepare(any())).thenThrow(new IllegalStateException("boom"));

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString())).isEqualTo(OnboardingCli.EXIT_ERROR);
    }

    @Test
    void run_import_readsTheStateAndTheKeyMaterial() throws Exception {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        Path keyMaterial = Files.write(directory.resolve("material.bin"), new byte[] {4, 5, 6});
        when(onboarding.importKey(any())).thenReturn(new ImportResult("arn", UUID.randomUUID(), Operation.REPLACE, "ab"));

        int exitCode = run("import", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString(),
                "--key-material", keyMaterial.toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<ImportCommand> command = ArgumentCaptor.forClass(ImportCommand.class);
        verify(onboarding).importKey(command.capture());
        assertThat(command.getValue().prepared()).isEqualTo(prepared());
        assertThat(command.getValue().importToken()).containsExactly(7);
        assertThat(command.getValue().encryptedKeyMaterial()).containsExactly(4, 5, 6);
        assertThat(out()).contains("Replace");
    }

    @Test
    void run_importDryRun_doesNotNeedTheKeyMaterial() throws Exception {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.importKey(any())).thenReturn(new ImportResult("arn", null, Operation.CREATE, "ab"));

        int exitCode = run("import", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString(),
                "--dry-run");

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<ImportCommand> command = ArgumentCaptor.forClass(ImportCommand.class);
        verify(onboarding).importKey(command.capture());
        assertThat(command.getValue().dryRun()).isTrue();
    }

    @Test
    void run_reconcile_usesTheDefaultGraceOf160Seconds() {
        when(reconciler.reconcile(any(), anyBoolean())).thenReturn(new ReconcileReport(2, List.of()));

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);

        verify(reconciler).reconcile(Duration.ofSeconds(160), false);
        assertThat(out()).contains("2");
    }

    @Test
    void run_reconcileWithGraceAndDryRun_passesThemOn() {
        when(reconciler.reconcile(any(), anyBoolean())).thenReturn(new ReconcileReport(0, List.of()));

        run("reconcile", "--grace-seconds=30", "--dry-run");

        verify(reconciler).reconcile(Duration.ofSeconds(30), true);
    }

    @Test
    void run_reconcileWithFailures_exitsWithOne() {
        when(reconciler.reconcile(any(), anyBoolean()))
                .thenReturn(new ReconcileReport(1, List.of("tenant cgcom: boom")));

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_ERROR);

        assertThat(err()).contains("tenant cgcom: boom");
    }

    @Test
    void run_deletionWindowOutsideTheKmsRange_isAUsageError() {
        assertThat(run("reconcile", "--deletion-window-days", "3")).isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_neverPrintsTheDatabasePassword() throws Exception {
        when(onboarding.prepare(any())).thenThrow(new OnboardingFailedException("database error"));

        run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir", directory.toString());
        run("--help");

        assertThat(out() + err()).doesNotContain(PASSWORD);
        assertThat(openedWith.get().toString()).doesNotContain(PASSWORD);
    }

    @Test
    void run_importOfARenewal_needsNoKeyMaterial() throws Exception {
        var renewal = new PreparedOnboarding("op-2", "cgcom", "arn:aws:kms:eu-west-1:000000000000:key/abc", null,
                List.of("AAAA"), "ab".repeat(32), Instant.parse("2026-10-27T12:00:00Z"), null, true, null);
        new PreparedOnboardingFiles(directory).write(renewal, null, null);
        when(onboarding.importKey(any())).thenReturn(new ImportResult("arn", UUID.randomUUID(), Operation.REPLACE, "ab"));

        int exitCode = run("import", "--state", directory.resolve("own-key-cgcom-op-2.state.json").toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<ImportCommand> command = ArgumentCaptor.forClass(ImportCommand.class);
        verify(onboarding).importKey(command.capture());
        assertThat(command.getValue().prepared().renewal()).isTrue();
        assertThat(command.getValue().importToken()).isNull();
    }

    @Test
    void run_importOfANewKeyWithoutKeyMaterial_isAUsageError() throws Exception {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});

        assertThat(run("import", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString()))
                .isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_discard_readsTheStateAndReportsTheOutcome() throws Exception {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.discard(any())).thenReturn(new DiscardResult("arn", DiscardOutcome.DISCARDED));

        int exitCode = run("discard", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<DiscardCommand> command = ArgumentCaptor.forClass(DiscardCommand.class);
        verify(onboarding).discard(command.capture());
        assertThat(command.getValue().prepared()).isEqualTo(prepared());
        assertThat(command.getValue().dryRun()).isFalse();
        assertThat(out()).contains("discarded");
    }

    @Test
    void run_discardDryRun_passesTheFlagOn() throws Exception {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.discard(any())).thenReturn(new DiscardResult("arn", DiscardOutcome.WOULD_DISCARD));

        run("discard", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString(), "--dry-run");

        ArgumentCaptor<DiscardCommand> command = ArgumentCaptor.forClass(DiscardCommand.class);
        verify(onboarding).discard(command.capture());
        assertThat(command.getValue().dryRun()).isTrue();
        assertThat(out()).contains("dry run");
    }

    @Test
    void run_discardRefused_exitsWithTwo() throws Exception {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.discard(any())).thenThrow(
                new OnboardingRejectedException(RejectionReason.POLICY_DENIED, "the key has been imported"));

        assertThat(run("discard", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString()))
                .isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(err()).contains("REJECTED: the key has been imported");
    }
}
