package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingUsageException;
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
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
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
    private final Properties systemProperties = new Properties();
    /** The tests are of a non-production environment unless one sets this: production is the default of the tool. */
    private boolean production;
    private String account = "123456789012";
    private OnboardingCli cli;

    @TempDir
    Path directory;

    @BeforeEach
    void setUp() {
        when(reconciler.reconcile(any(), anyBoolean())).thenReturn(new ReconcileReport(0, List.of()));
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
        }, new PrintStream(stdout, true, StandardCharsets.UTF_8), new PrintStream(stderr, true, StandardCharsets.UTF_8),
                systemProperties);
    }

    private int run(String... args) {
        return cli.run(withMode(args), env);
    }

    /** The mode is a command line argument: non-production, or production with the account it is for. */
    private String[] withMode(String[] args) {
        if (args.length == 0 || args[0].startsWith("-")) {
            return args;
        }
        List<String> all = new ArrayList<>(List.of(args));
        if (!production) {
            all.add("--non-production");
        } else if (account != null) {
            all.add("--expected-aws-account");
            all.add(account);
        }
        return all.toArray(String[]::new);
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
    void run_argumentThatIsNotAnOption_isAUsageError() {
        assertThat(run("reconcile", "cgcom")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("unexpected argument 'cgcom'");
    }

    @Test
    void run_optionGivenTwice_isAUsageError() {
        assertThat(run("reconcile", "--grace-seconds", "30", "--grace-seconds=40")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--grace-seconds is given twice");
        verifyNoInteractions(reconciler);
    }

    @Test
    void run_lastOptionWithoutItsValue_isAUsageError() {
        assertThat(cli.run(new String[] {"reconcile", "--non-production", "--grace-seconds"}, env))
                .isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--grace-seconds needs a value");
    }

    @Test
    void run_optionValueAsTheNextArgument_isTheValue() {
        assertThat(run("reconcile", "--grace-seconds", "30")).isEqualTo(OnboardingCli.EXIT_OK);

        verify(reconciler).reconcile(Duration.ofSeconds(30), false);
    }

    @Test
    void run_optionMissingOnTheCommandLine_isTakenFromTheEnvironment() {
        env.put("OWN_KEY_GRACE_SECONDS", "45");
        env.put("OWN_KEY_DRY_RUN", "yes");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);

        verify(reconciler).reconcile(Duration.ofSeconds(45), true);
    }

    @Test
    void run_optionOnTheCommandLine_winsOverTheEnvironment() {
        env.put("OWN_KEY_GRACE_SECONDS", "45");

        assertThat(run("reconcile", "--grace-seconds", "30")).isEqualTo(OnboardingCli.EXIT_OK);

        verify(reconciler).reconcile(Duration.ofSeconds(30), false);
    }

    @Test
    void run_switchFromTheEnvironmentThatIsNotTrue_isNotSet() {
        env.put("OWN_KEY_DRY_RUN", "no");
        env.put("OWN_KEY_GRACE_SECONDS", " ");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);

        verify(reconciler).reconcile(Duration.ofSeconds(160), false);
    }

    @Test
    void run_missingRequiredOption_isAUsageErrorNamingTheEnvironmentVariable() throws Exception {
        assertThat(run("prepare", "--cert-chain", chainFile().toString(), "--out-dir", directory.toString()))
                .isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--tenant", "OWN_KEY_TENANT");
    }

    @Test
    void run_missingDatabasePassword_isAUsageError() {
        env.remove("SPRING_R2DBC_PASSWORD");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("SPRING_R2DBC_PASSWORD");
    }

    @Test
    void run_withoutNonProduction_theProductionChecksApplyAndNeedTheTrustAnchor() throws Exception {
        production = true;

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--expected-org-id", "VATES-Q0000000X", "--key-policy", "k.json"))
                .isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--trust-anchor", "--non-production");
        verifyNoInteractions(onboarding);
    }

    @Test
    void run_prepareInProductionWithoutAKeyPolicy_isAUsageError() throws Exception {
        production = true;
        Path anchor = chainFile();

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--expected-org-id", "VATES-Q0000000X", "--trust-anchor", anchor.toString()))
                .isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("explicit key policy");
        verifyNoInteractions(onboarding);
    }

    @Test
    void run_prepareInProductionWithEverythingGiven_usesTheProductionPolicyAndTheKeyPolicy() throws Exception {
        production = true;
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));
        Path chain = chainFile();
        Path keyPolicy = Files.writeString(directory.resolve("policy.json"), "{\"Version\":\"2012-10-17\"}");

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chain.toString(), "--out-dir",
                directory.toString(), "--trust-anchor", chain.toString(), "--expected-org-id", "VATES-Q0000000X",
                "--key-policy", keyPolicy.toString());

        assertThat(exitCode).as(err()).isEqualTo(OnboardingCli.EXIT_OK);
        ArgumentCaptor<PrepareCommand> command = ArgumentCaptor.forClass(PrepareCommand.class);
        verify(onboarding).prepare(command.capture());
        assertThat(command.getValue().policy().production()).isTrue();
        assertThat(command.getValue().policy().expectedOrganizationIdentifier()).isEqualTo("VATES-Q0000000X");
        assertThat(openedWith.get().keyPolicy()).isEqualTo("{\"Version\":\"2012-10-17\"}");
    }

    @Test
    void run_prepare_printsAndLogsTheSha256OfTheKeyPolicyButNeverItsContent() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));
        String content = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        Path keyPolicy = Files.writeString(directory.resolve("policy.json"), content);
        String sha256 = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8)));
        Logger cliLogger = (Logger) LoggerFactory.getLogger(OnboardingCli.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        cliLogger.addAppender(appender);
        try {
            int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                    directory.toString(), "--key-policy", keyPolicy.toString());

            assertThat(exitCode).as(err()).isEqualTo(OnboardingCli.EXIT_OK);
            assertThat(out()).contains("key policy  : sha256 " + sha256).doesNotContain("2012-10-17");
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage)
                    .anyMatch(message -> message.contains(sha256)).noneMatch(message -> message.contains("2012-10-17"));
        } finally {
            cliLogger.detachAppender(appender);
        }
    }

    @Test
    void run_prepareWithoutAKeyPolicy_saysTheKmsDefaultWasUsed() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));

        run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir", directory.toString());

        assertThat(out()).contains("key policy  : none (the KMS default policy");
    }

    @Test
    void run_importCommittedButStateNotMarkedAsConsumed_warnsOnStderrAndStillSucceeds() {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        Path state = directory.resolve("own-key-cgcom-op-1.state.json");
        when(onboarding.importKey(any())).thenReturn(new ImportResult("arn:aws:kms:eu-west-1:000000000000:key/abc",
                UUID.randomUUID(), Operation.CREATE, "ab".repeat(32), false));

        int exitCode = run("import", "--state", state.toString(), "--key-material",
                directory.resolve("own-key-cgcom-op-1.import-token.bin").toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        assertThat(err()).contains("WARNING", "Do NOT use it again", state.toString());
    }

    @Test
    void run_importWithTheStateMarkedAsConsumed_printsNoWarning() {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.importKey(any())).thenReturn(new ImportResult("arn:aws:kms:eu-west-1:000000000000:key/abc",
                UUID.randomUUID(), Operation.CREATE, "ab".repeat(32)));

        int exitCode = run("import", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString(),
                "--key-material", directory.resolve("own-key-cgcom-op-1.import-token.bin").toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_OK);
        assertThat(err()).doesNotContain("WARNING");
    }

    @Test
    void run_keyPolicyThatIsNotJson_isAUsageError() throws Exception {
        Path notJson = Files.writeString(directory.resolve("policy.json"), "not json");

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--key-policy", notJson.toString())).isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_prepareInProductionWithTheKeyPolicyInTheEnvironment_passesItAndPrintsItsSha256() throws Exception {
        production = true;
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));
        String content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Gestión\"}]}";
        env.put("OWN_KEY_KEY_POLICY_JSON", content);
        Path chain = chainFile();

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chain.toString(), "--out-dir",
                directory.toString(), "--trust-anchor", chain.toString(), "--expected-org-id", "VATES-Q0000000X");

        assertThat(exitCode).as(err()).isEqualTo(OnboardingCli.EXIT_OK);
        assertThat(openedWith.get().keyPolicy()).isEqualTo(content);
        assertThat(out()).contains("key policy  : sha256 " + sha256Hex(content.getBytes(StandardCharsets.UTF_8)))
                .doesNotContain("2012-10-17");
    }

    @Test
    void run_keyPolicyFileWithNonAsciiText_hashesTheUtf8BytesThatArePassedOn() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));
        String content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Gestión\"}]}";
        Path keyPolicy = Files.write(directory.resolve("policy.json"), content.getBytes(StandardCharsets.UTF_8));

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--key-policy", keyPolicy.toString());

        assertThat(exitCode).as(err()).isEqualTo(OnboardingCli.EXIT_OK);
        assertThat(openedWith.get().keyPolicy()).isEqualTo(content);
        assertThat(out()).contains("key policy  : sha256 " + sha256Hex(Files.readAllBytes(keyPolicy)));
    }

    @Test
    void run_keyPolicyFileAndKeyPolicyInTheEnvironment_isAUsageError() throws Exception {
        Path keyPolicy = Files.writeString(directory.resolve("policy.json"), "{\"Version\":\"2012-10-17\"}");
        env.put("OWN_KEY_KEY_POLICY_JSON", "{\"Version\":\"2012-10-17\"}");

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--key-policy", keyPolicy.toString())).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("given twice", "OWN_KEY_KEY_POLICY_JSON");
        verifyNoInteractions(onboarding);
    }

    @Test
    void run_keyPolicyFileWithAByteOrderMark_isAUsageError() throws Exception {
        byte[] withBom = ("﻿{\"Version\":\"2012-10-17\"}").getBytes(StandardCharsets.UTF_8);
        Path keyPolicy = Files.write(directory.resolve("policy.json"), withBom);

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--key-policy", keyPolicy.toString())).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("byte order mark");
        verifyNoInteractions(onboarding);
    }

    @Test
    void run_keyPolicyInTheEnvironmentWithAByteOrderMark_isAUsageError() throws Exception {
        env.put("OWN_KEY_KEY_POLICY_JSON", "﻿{\"Version\":\"2012-10-17\"}");

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString())).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("OWN_KEY_KEY_POLICY_JSON", "byte order mark");
    }

    @Test
    void run_keyPolicyFileThatIsNotUtf8_isAUsageError() throws Exception {
        // "Gestión" in ISO-8859-1: the 0xF3 byte alone is not UTF-8
        byte[] latin1 = "{\"Version\":\"2012-10-17\",\"Sid\":\"Gestión\"}".getBytes(StandardCharsets.ISO_8859_1);
        Path keyPolicy = Files.write(directory.resolve("policy.json"), latin1);

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString(), "--key-policy", keyPolicy.toString())).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("not valid UTF-8");
        verifyNoInteractions(onboarding);
    }

    @Test
    void run_keyPolicyInTheEnvironmentForAnotherCommand_isIgnored() {
        env.put("OWN_KEY_KEY_POLICY_JSON", "not even json");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    @Test
    void run_nonProductionWithoutAKeyPolicy_goesAheadWithTheKmsDefault() throws Exception {
        when(onboarding.prepare(any())).thenReturn(new PrepareResult(prepared(), Operation.CREATE, "ab".repeat(32)));

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString())).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(openedWith.get().keyPolicy()).isNull();
    }

    @Test
    void run_kmsEndpointWithoutNonProduction_isAUsageError() {
        production = true;

        assertThat(run("reconcile", "--kms-endpoint", "http://localhost:4566")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--non-production");
        assertThat(openedWith.get()).isNull();
    }

    @Test
    void run_productionImportNeedsTheTrustAnchorAndTheOrganizationToo() {
        production = true;
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});

        assertThat(run("import", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString(),
                "--key-material", directory.resolve("own-key-cgcom-op-1.import-token.bin").toString()))
                .isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_nonProductionFromTheEnvironment_isAUsageErrorBecauseItIsNoLongerAccepted() {
        env.put("OWN_KEY_NON_PRODUCTION", "true");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("OWN_KEY_NON_PRODUCTION", "no longer accepted");
        assertThat(openedWith.get()).isNull();
    }

    @Test
    void run_nonProductionFalseOnTheCommandLine_isProduction() {
        production = true;

        assertThat(run("reconcile", "--non-production=false")).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(openedWith.get().production()).isTrue();
        assertThat(out()).contains("checks: production");
    }

    @Test
    void run_production_needsTheExpectedAwsAccount() {
        production = true;
        account = null;

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("--expected-aws-account", "OWN_KEY_EXPECTED_AWS_ACCOUNT");
        assertThat(openedWith.get()).isNull();
    }

    @Test
    void run_productionWithTheAccountFromTheEnvironment_passesItToTheSettings() {
        production = true;
        account = null;
        env.put("OWN_KEY_EXPECTED_AWS_ACCOUNT", "210987654321");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(openedWith.get().expectedAwsAccount()).isEqualTo("210987654321");
        assertThat(openedWith.get().production()).isTrue();
    }

    @Test
    void run_expectedAwsAccountThatIsNotTwelveDigits_isAUsageError() {
        assertThat(run("reconcile", "--expected-aws-account", "12345")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("12-digit");
        assertThat(openedWith.get()).isNull();
    }

    @Test
    void run_nonProduction_doesNotNeedTheAccountAndSaysItsModeOnStdout() {
        account = null;

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);

        assertThat(openedWith.get().expectedAwsAccount()).isNull();
        assertThat(openedWith.get().production()).isFalse();
        assertThat(out()).contains("checks: NON-PRODUCTION");
    }

    @Test
    void run_productionWithAnSdkEndpointVariable_isRefused() {
        production = true;
        env.put("AWS_ENDPOINT_URL_STS", "http://localhost:4566");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("AWS_ENDPOINT_URL_STS").doesNotContain("localhost:4566");
        assertThat(openedWith.get()).isNull();
    }

    @Test
    void run_productionWithTheGeneralSdkEndpointVariable_isRefused() {
        production = true;
        env.put("AWS_ENDPOINT_URL", "http://localhost:4566");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("AWS_ENDPOINT_URL");
    }

    @Test
    void run_productionWithAnSdkEndpointSystemProperty_isRefused() {
        production = true;
        systemProperties.setProperty("aws.endpointUrlSts", "http://localhost:4566");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_USAGE);

        assertThat(err()).contains("aws.endpointUrlSts");
        assertThat(openedWith.get()).isNull();
    }

    @Test
    void run_nonProductionWithSdkEndpointVariables_isAllowed() {
        env.put("AWS_ENDPOINT_URL", "http://localhost:4566");
        systemProperties.setProperty("aws.endpointUrl", "http://localhost:4566");

        assertThat(run("reconcile")).isEqualTo(OnboardingCli.EXIT_OK);
    }

    @Test
    void run_tenantIdUnknown_isAUsageError() throws Exception {
        when(onboarding.prepare(any())).thenThrow(new OnboardingUsageException("'unknown' is not a tenant id"));

        assertThat(run("prepare", "--tenant", "unknown", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString())).isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_anIllegalArgumentExceptionOfALibrary_isNotAUsageError() throws Exception {
        when(onboarding.prepare(any())).thenThrow(new IllegalArgumentException("boom"));

        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", chainFile().toString(), "--out-dir",
                directory.toString())).isEqualTo(OnboardingCli.EXIT_ERROR);
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
    void run_importDryRun_doesNotNeedTheKeyMaterial() {
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
    void run_importOfARenewal_needsNoKeyMaterial() {
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
    void run_importOfANewKeyWithoutKeyMaterial_isAUsageError() {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});

        assertThat(run("import", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString()))
                .isEqualTo(OnboardingCli.EXIT_USAGE);
    }

    @Test
    void run_discard_readsTheStateAndReportsTheOutcome() {
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
    void run_discardDryRun_passesTheFlagOn() {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.discard(any())).thenReturn(new DiscardResult("arn", DiscardOutcome.WOULD_DISCARD));

        run("discard", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString(), "--dry-run");

        ArgumentCaptor<DiscardCommand> command = ArgumentCaptor.forClass(DiscardCommand.class);
        verify(onboarding).discard(command.capture());
        assertThat(command.getValue().dryRun()).isTrue();
        assertThat(out()).contains("dry run");
    }

    @Test
    void run_discardRefused_exitsWithTwo() {
        new PreparedOnboardingFiles(directory).write(prepared(), new byte[] {1}, new byte[] {7});
        when(onboarding.discard(any())).thenThrow(
                new OnboardingRejectedException(RejectionReason.POLICY_DENIED, "the key has been imported"));

        assertThat(run("discard", "--state", directory.resolve("own-key-cgcom-op-1.state.json").toString()))
                .isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(err()).contains("REJECTED: the key has been imported");
    }

    @Test
    void run_auditSinkDefaultsToTheLog() {
        run("reconcile");

        assertThat(openedWith.get().auditSink()).isEqualTo(OnboardingSettings.AuditSinkMode.LOG);
    }

    @Test
    void run_auditSinkOutbox_fromTheArgumentOrTheEnvironment() {
        run("reconcile", "--audit-sink", "outbox");
        assertThat(openedWith.get().auditSink()).isEqualTo(OnboardingSettings.AuditSinkMode.OUTBOX);

        env.put("OWN_KEY_AUDIT_SINK", "OUTBOX");
        run("reconcile");
        assertThat(openedWith.get().auditSink()).isEqualTo(OnboardingSettings.AuditSinkMode.OUTBOX);
    }

    @Test
    void run_auditSinkOfAnotherKind_isAUsageError() {
        assertThat(run("reconcile", "--audit-sink", "kafka")).isEqualTo(OnboardingCli.EXIT_USAGE);
    }
}
