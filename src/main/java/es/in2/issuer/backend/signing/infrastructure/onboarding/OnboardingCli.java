package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingPolicy;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingUsageException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyCertificateValidator;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.DiscardCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler.ReconcileReport;
import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Command line of the own-key onboarding tool: {@code prepare}, {@code import} and {@code reconcile}. It is
 * independent of how it is launched (laptop, a one-off ECS task, a scheduled job): commands and parameters
 * come from arguments or environment variables, the result is the exit code.
 *
 * <p>Exit codes: {@value #EXIT_OK} ok; {@value #EXIT_ERROR} any other error; {@value #EXIT_REJECTED} the
 * onboarding was rejected by a validation (the reason is on stderr; nothing was put into service);
 * {@value #EXIT_USAGE} usage error.
 *
 * <p>There is no withdrawal command: a configuration is withdrawn by its replacement ({@code import}), and
 * {@code reconcile} retires the KMS key of a replaced configuration once the grace period has passed.
 */
@Slf4j
public final class OnboardingCli {

    public static final int EXIT_OK = 0;
    public static final int EXIT_ERROR = 1;
    public static final int EXIT_REJECTED = 2;
    public static final int EXIT_USAGE = 64;

    private static final long DEFAULT_GRACE_SECONDS = 160;
    private static final int DEFAULT_DELETION_WINDOW_DAYS = 7;

    /** Opens the collaborators of one run. */
    @FunctionalInterface
    public interface Wiring {
        Services open(OnboardingSettings settings);
    }

    /** The use cases of one run, and the clients behind them, which {@link #close()} releases. */
    public interface Services extends AutoCloseable {
        OwnKeyOnboarding onboarding();

        OwnKeyReconciler reconciler();

        @Override
        void close();
    }

    private enum Command {
        PREPARE("prepare"),
        IMPORT("import"),
        DISCARD("discard"),
        RECONCILE("reconcile");

        private final String word;

        Command(String word) {
            this.word = word;
        }
    }

    private enum Opt {
        DB_URL("db-url", "SPRING_FLYWAY_URL", false),
        DB_USER("db-user", "SPRING_R2DBC_USERNAME", false),
        KMS_REGION("kms-region", "ISSUER_SIGNING_KMS_REGION", false),
        KMS_ENDPOINT("kms-endpoint", "ISSUER_SIGNING_KMS_ENDPOINT", false),
        DELETION_WINDOW_DAYS("deletion-window-days", "OWN_KEY_DELETION_WINDOW_DAYS", false),
        DRY_RUN("dry-run", "OWN_KEY_DRY_RUN", true),
        AUDIT_SINK("audit-sink", "OWN_KEY_AUDIT_SINK", false),
        TENANT("tenant", "OWN_KEY_TENANT", false),
        CERT_CHAIN("cert-chain", "OWN_KEY_CERT_CHAIN", false),
        OUT_DIR("out-dir", "OWN_KEY_OUT_DIR", false),
        ALIAS("alias", "OWN_KEY_ALIAS", false),
        /** Command line only: an environment variable inherited from another environment must not weaken the checks. */
        NON_PRODUCTION("non-production", null, true),
        EXPECTED_AWS_ACCOUNT("expected-aws-account", "OWN_KEY_EXPECTED_AWS_ACCOUNT", false),
        KEY_POLICY("key-policy", "OWN_KEY_KEY_POLICY", false),
        TRUST_ANCHOR("trust-anchor", "OWN_KEY_TRUST_ANCHOR", false),
        EXPECTED_ORG_ID("expected-org-id", "OWN_KEY_EXPECTED_ORG_ID", false),
        STATE("state", "OWN_KEY_STATE", false),
        KEY_MATERIAL("key-material", "OWN_KEY_KEY_MATERIAL", false),
        IMPORT_TOKEN("import-token", "OWN_KEY_IMPORT_TOKEN", false),
        GRACE_SECONDS("grace-seconds", "OWN_KEY_GRACE_SECONDS", false);

        private final String flag;
        private final String env;
        private final boolean isSwitch;

        Opt(String flag, String env, boolean isSwitch) {
            this.flag = flag;
            this.env = env;
            this.isSwitch = isSwitch;
        }
    }

    private static final String ENV_DB_PASSWORD = "SPRING_R2DBC_PASSWORD";
    private static final String ENV_AWS_REGION = "AWS_REGION";
    /** No longer read: its presence is an error, so that a leftover cannot go unnoticed. */
    private static final String ENV_NON_PRODUCTION_REMOVED = "OWN_KEY_NON_PRODUCTION";
    private static final String ENV_ENDPOINT_PREFIX = "AWS_ENDPOINT_URL";
    private static final String PROPERTY_ENDPOINT_PREFIX = "aws.endpointUrl";

    private static final Set<Opt> COMMON = EnumSet.of(Opt.DB_URL, Opt.DB_USER, Opt.KMS_REGION, Opt.KMS_ENDPOINT,
            Opt.DELETION_WINDOW_DAYS, Opt.DRY_RUN, Opt.AUDIT_SINK, Opt.NON_PRODUCTION, Opt.EXPECTED_AWS_ACCOUNT);

    private static final String HELP = """
            Own-key onboarding tool (EUD-289): puts a tenant's own signing key, held in AWS KMS, into service.

            Usage: <launcher> <command> [options]

            Commands
              prepare    Validate the certificate chain, create the KMS key (tagged Tenant=<tenant>) and leave
                         the wrapping public key, the import token and a state file in --out-dir. The customer
                         wraps its private key with the public key.
              import     Validate again, import the wrapped key material, check that the key is the certificate's
                         and, in one transaction, replace the tenant's active configuration with the new one.
              discard    Give up a preparation that was never imported: disable its KMS key if possible, schedule
                         its deletion, delete its alias and mark the state file. Refused (exit 2) if the key has
                         key material, other tags than this preparation's, or is referenced by any configuration.
              reconcile  Disable and schedule the deletion of the KMS key of every replaced configuration
                         withdrawn for longer than the grace period. Safe to repeat.

            Every command accepts --dry-run: validations only, nothing is written to KMS, files or the database.
            An option can also be given as an environment variable (name in brackets).

            Common options
              --db-url <jdbc url>            [SPRING_FLYWAY_URL]
              --db-user <user>               [SPRING_R2DBC_USERNAME]
              (database password)            [SPRING_R2DBC_PASSWORD], environment only
              --kms-region <region>          [ISSUER_SIGNING_KMS_REGION, then AWS_REGION]
              --kms-endpoint <url>           [ISSUER_SIGNING_KMS_ENDPOINT] emulators only (needs --non-production); KMS and STS
              --deletion-window-days <7-30>  [OWN_KEY_DELETION_WINDOW_DAYS] default 7
              --dry-run                      [OWN_KEY_DRY_RUN]
              --expected-aws-account <id>    [OWN_KEY_EXPECTED_AWS_ACCOUNT] 12-digit AWS account the credentials must
                                             belong to (STS GetCallerIdentity); required unless --non-production.
                                             A different account ends with exit 2 before KMS or the database are used
              --non-production               command line only (an environment variable is not accepted): STG and
                                             local environments only. Accepts a self-signed certificate, a missing trust
                                             anchor, organization id, key policy and account, and --kms-endpoint and the
                                             SDK endpoint variables. Without it the production checks apply, and the run
                                             refuses AWS_ENDPOINT_URL* variables and aws.endpointUrl* properties
              --audit-sink <log|outbox>      [OWN_KEY_AUDIT_SINK] default log; outbox needs a build with the audit starter

            prepare
              --tenant <id>                  [OWN_KEY_TENANT] tenant id, e.g. cgcom
              --cert-chain <pem file>        [OWN_KEY_CERT_CHAIN] leaf first, root excluded
              --out-dir <dir>                [OWN_KEY_OUT_DIR]
              --alias <alias/name>           [OWN_KEY_ALIAS] default alias/own-key-<tenant>-<operation id>
              --key-policy <json file>       [OWN_KEY_KEY_POLICY] key policy of the new key; required unless
                                             --non-production (then, without it, the KMS default policy is used)
            import
              --state <file>                 [OWN_KEY_STATE] the state file written by prepare
              --key-material <file>          [OWN_KEY_KEY_MATERIAL] the private key wrapped by the customer;
                                             not needed for a renewal (a certificate for the active key)
              --import-token <file>          [OWN_KEY_IMPORT_TOKEN] default: the one next to the state file
            discard
              --state <file>                 [OWN_KEY_STATE] the state file of the preparation to give up
            prepare and import
              --trust-anchor <pem file>      [OWN_KEY_TRUST_ANCHOR] the CA agreed with the tenant (root or intermediate);
                                             required unless --non-production
              --expected-org-id <id>         [OWN_KEY_EXPECTED_ORG_ID] organizationIdentifier of the tenant;
                                             required unless --non-production
              import refuses a policy laxer than or different from the one prepare ran with
            reconcile
              --grace-seconds <n>            [OWN_KEY_GRACE_SECONDS] default 160

            Exit codes: 0 ok; 1 any other error; 2 onboarding rejected by a validation (reason on stderr);
            64 usage error.
            """;

    private final Wiring wiring;
    private final PrintStream out;
    private final PrintStream err;
    private final Properties systemProperties;

    public OnboardingCli(Wiring wiring, PrintStream out, PrintStream err) {
        this(wiring, out, err, System.getProperties());
    }

    /** @param systemProperties where the {@code aws.endpointUrl*} properties of the SDK are looked for */
    public OnboardingCli(Wiring wiring, PrintStream out, PrintStream err, Properties systemProperties) {
        this.wiring = wiring;
        this.out = out;
        this.err = err;
        this.systemProperties = systemProperties;
    }

    /** The command line, resolved against the environment. */
    private record Invocation(Command command, Map<Opt, String> values, Map<String, String> env) {

        private String get(Opt option) {
            return values.get(option);
        }

        private boolean has(Opt option) {
            return values.containsKey(option);
        }

        private String require(Opt option) {
            String value = values.get(option);
            if (value == null || value.isBlank()) {
                throw new OnboardingUsageException("--" + option.flag + " (or " + option.env + ") is required");
            }
            return value;
        }

        private boolean dryRun() {
            return has(Opt.DRY_RUN);
        }
    }

    /** @return the exit code */
    public int run(String[] args, Map<String, String> env) {
        try {
            if (args.length == 0) {
                throw new OnboardingUsageException("a command is required: prepare, import, discard or reconcile");
            }
            if (List.of("--help", "-h", "help").contains(args[0])) {
                out.print(HELP);
                return EXIT_OK;
            }
            Invocation invocation = parse(args, env);
            if (invocation == null) {
                out.print(HELP);
                return EXIT_OK;
            }
            return execute(invocation);
        } catch (OnboardingUsageException e) {
            err.println("USAGE: " + e.getMessage() + " (run with --help)");
            return EXIT_USAGE;
        } catch (OnboardingRejectedException e) {
            err.println("REJECTED: " + e.getMessage());
            return EXIT_REJECTED;
        } catch (OnboardingFailedException e) {
            err.println("ERROR: " + e.getMessage());
            return EXIT_ERROR;
        } catch (RuntimeException e) {
            err.println("ERROR: unexpected " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return EXIT_ERROR;
        }
    }

    private int execute(Invocation invocation) {
        requireProductionSafeUsage(invocation);
        KeyPolicy keyPolicy = keyPolicy(invocation);
        OnboardingSettings settings = settings(invocation, keyPolicy == null ? null : keyPolicy.json());
        announceChecks(invocation);
        try (Services services = wiring.open(settings)) {
            return switch (invocation.command()) {
                case PREPARE -> {
                    prepare(invocation, services.onboarding(), keyPolicy);
                    yield EXIT_OK;
                }
                case IMPORT -> {
                    importKey(invocation, services.onboarding());
                    yield EXIT_OK;
                }
                case DISCARD -> discard(invocation, services.onboarding());
                case RECONCILE -> reconcile(invocation, services.reconciler());
            };
        }
    }

    /** Ends normally or throws: a failure never comes back as an exit code. */
    private void prepare(Invocation invocation, OwnKeyOnboarding onboarding, KeyPolicy keyPolicy) {
        String tenant = invocation.require(Opt.TENANT);
        String chainPem = readString(Path.of(invocation.require(Opt.CERT_CHAIN)));
        Path outDir = invocation.dryRun() ? null : Path.of(invocation.require(Opt.OUT_DIR));
        OnboardingPolicy policy = policy(invocation);
        var result = onboarding.prepare(new PrepareCommand(tenant, chainPem, policy, invocation.get(Opt.ALIAS),
                invocation.dryRun(), outDir == null ? null : new PreparedOnboardingFiles(outDir)));
        if (result.prepared() == null) {
            out.println("dry run: the certificate chain and the tenant pass the validations (operation "
                    + result.operation().catalogName() + "); nothing was created");
            return;
        }
        var prepared = result.prepared();
        if (prepared.renewal()) {
            out.println("prepared the renewal " + prepared.operationId() + " for tenant " + prepared.tenant()
                    + " (operation " + result.operation().catalogName() + "): the certificate renews the key "
                    + prepared.keyArn() + ", which stays; nothing was created in KMS");
            out.println("next       : run import with --state " + outDir.resolve(prefixOf(prepared) + ".state.json")
                    + " (no key material is needed)");
            return;
        }
        String prefix = prefixOf(prepared);
        out.println("prepared onboarding " + prepared.operationId() + " for tenant " + prepared.tenant()
                + " (operation " + result.operation().catalogName() + ")");
        out.println("key        : " + prepared.keyArn());
        out.println("alias      : " + prepared.alias());
        out.println("SPKI sha256: " + prepared.spkiSha256());
        printKeyPolicy(keyPolicy);
        out.println("valid until: " + prepared.importTokenExpiresAt() + " (import token and wrapping key)");
        out.println("files      : " + outDir.resolve(prefix + ".{wrapping-public-key.der,wrapping-public-key.pem,"
                + "import-token.bin,state.json}"));
        out.println("next       : the customer wraps its private key with the wrapping public key; then run import "
                + "with --state " + outDir.resolve(prefix + ".state.json") + " and --key-material <wrapped key>");
    }

    /** What policy the new key was created with is shown by its SHA-256, never by its content. */
    private void printKeyPolicy(KeyPolicy keyPolicy) {
        if (keyPolicy == null) {
            out.println("key policy  : none (the KMS default policy, --non-production only)");
            log.info("The key was created with the KMS default policy");
            return;
        }
        out.println("key policy  : sha256 " + keyPolicy.sha256() + " (the content is not printed)");
        log.info("Key policy applied to the new key: sha256={}", keyPolicy.sha256());
    }

    /** Ends normally or throws: a failure never comes back as an exit code. */
    private void importKey(Invocation invocation, OwnKeyOnboarding onboarding) {
        Path stateFile = Path.of(invocation.require(Opt.STATE));
        Path tokenFile = invocation.has(Opt.IMPORT_TOKEN) ? Path.of(invocation.get(Opt.IMPORT_TOKEN)) : null;
        var loaded = PreparedOnboardingFiles.read(stateFile, tokenFile);
        boolean needsKeyMaterial = !loaded.prepared().renewal() && !invocation.dryRun();
        byte[] keyMaterial = invocation.has(Opt.KEY_MATERIAL) || needsKeyMaterial
                ? readBytes(Path.of(invocation.require(Opt.KEY_MATERIAL))) : new byte[0];
        var result = onboarding.importKey(new ImportCommand(loaded.prepared(), loaded.importToken(), keyMaterial,
                policy(invocation), invocation.dryRun(), PreparedOnboardingFiles.around(stateFile)));
        if (result.configurationId() == null) {
            out.println("dry run: the onboarding of tenant " + loaded.prepared().tenant()
                    + " passes the validations (operation " + result.operation().catalogName() + "); nothing was imported");
            return;
        }
        out.println("tenant " + loaded.prepared().tenant() + " now signs with " + (loaded.prepared().renewal()
                ? "the renewed certificate of its own key" : "its own key") + " (operation "
                + result.operation().catalogName() + ")");
        out.println("key           : " + result.keyArn());
        out.println("configuration : " + result.configurationId());
        out.println("SPKI sha256   : " + result.spkiSha256());
        if (!result.stateMarkedAsConsumed()) {
            err.println("WARNING: the onboarding was committed, but the state file " + stateFile + " could not be marked as "
                    + "consumed. Do NOT use it again (a second import of a renewal would replace the configuration once "
                    + "more): delete it.");
        }
    }

    private int discard(Invocation invocation, OwnKeyOnboarding onboarding) {
        Path stateFile = Path.of(invocation.require(Opt.STATE));
        var loaded = PreparedOnboardingFiles.read(stateFile, null);
        var result = onboarding.discard(new DiscardCommand(loaded.prepared(), invocation.dryRun(),
                PreparedOnboardingFiles.around(stateFile)));
        String what = switch (result.outcome()) {
            case DISCARDED -> "discarded: the key is disabled and scheduled for deletion, its alias is deleted and "
                    + "the state file is marked";
            case ALREADY_DISCARDED -> "nothing to do: the preparation was already discarded";
            case WOULD_DISCARD -> "dry run: the preparation can be discarded; nothing was changed";
        };
        out.println(what);
        out.println("key        : " + result.keyArn());
        return EXIT_OK;
    }

    private static String prefixOf(PreparedOnboarding prepared) {
        return "own-key-" + prepared.tenant() + "-" + prepared.operationId();
    }

    private int reconcile(Invocation invocation, OwnKeyReconciler reconciler) {
        long seconds = invocation.has(Opt.GRACE_SECONDS) ? parseLong(Opt.GRACE_SECONDS, invocation.get(Opt.GRACE_SECONDS))
                : DEFAULT_GRACE_SECONDS;
        if (seconds < 0) {
            throw new OnboardingUsageException("--grace-seconds must not be negative");
        }
        ReconcileReport report = reconciler.reconcile(Duration.ofSeconds(seconds), invocation.dryRun());
        out.println((invocation.dryRun() ? "dry run: keys that would be retired: " : "keys retired: ") + report.retired());
        if (!report.succeeded()) {
            report.failures().forEach(failure -> err.println("ERROR: " + failure));
            return EXIT_ERROR;
        }
        return EXIT_OK;
    }

    /**
     * The production checks are the default: what a non-production environment may skip must be said. Checked before
     * anything is opened, so a bad call costs nothing.
     */
    private void requireProductionSafeUsage(Invocation invocation) {
        if (invocation.env().containsKey(ENV_NON_PRODUCTION_REMOVED)) {
            throw new OnboardingUsageException(ENV_NON_PRODUCTION_REMOVED + " is no longer accepted: --non-production is "
                    + "only a command line argument, so that a variable inherited from another environment cannot "
                    + "weaken the checks. Remove the variable");
        }
        boolean production = !invocation.has(Opt.NON_PRODUCTION);
        if (invocation.has(Opt.EXPECTED_AWS_ACCOUNT)) {
            ExpectedAwsAccount.parse(invocation.get(Opt.EXPECTED_AWS_ACCOUNT));
        }
        if (production) {
            requireNoSdkEndpointOverride(invocation);
            requireForProduction(invocation, Opt.EXPECTED_AWS_ACCOUNT);
        }
        if (production && invocation.has(Opt.KMS_ENDPOINT)) {
            throw new OnboardingUsageException("--kms-endpoint (an emulator) is only accepted with --non-production: "
                    + "a redirected STS would also make the identity recorded as the actor untrustworthy");
        }
        if (production && (invocation.command() == Command.PREPARE || invocation.command() == Command.IMPORT)) {
            requireForProduction(invocation, Opt.TRUST_ANCHOR);
            requireForProduction(invocation, Opt.EXPECTED_ORG_ID);
        }
        if (invocation.command() == Command.PREPARE && !invocation.dryRun() && !invocation.has(Opt.KEY_POLICY)) {
            requireKeyPolicyUnlessNonProduction(production);
        }
    }

    private void requireKeyPolicyUnlessNonProduction(boolean production) {
        if (production) {
            throw new OnboardingUsageException("prepare does not create a key without an explicit key policy: "
                    + "--key-policy <json file> (or --non-production outside production)");
        }
        log.warn("No key policy was given (--non-production): the key is created with the KMS default policy, "
                + "which delegates everything to IAM of the account. Never do this in STG or PRO.");
    }

    /**
     * The SDK reads endpoint URLs from the environment and the system properties: a redirected STS would make the identity
     * recorded as the actor untrustworthy. Only the names are reported, never the values.
     */
    private void requireNoSdkEndpointOverride(Invocation invocation) {
        List<String> configured = new ArrayList<>();
        invocation.env().keySet().stream().filter(name -> name.toUpperCase(Locale.ROOT).startsWith(ENV_ENDPOINT_PREFIX))
                .sorted().forEach(configured::add);
        systemProperties.stringPropertyNames().stream().filter(name -> name.startsWith(PROPERTY_ENDPOINT_PREFIX))
                .sorted().forEach(configured::add);
        if (!configured.isEmpty()) {
            throw new OnboardingUsageException("the AWS SDK endpoint override " + configured + " is configured: the "
                    + "production checks refuse it, because a redirected STS would make the identity recorded as the "
                    + "actor untrustworthy. Remove it (or use --non-production in an environment that is not production)");
        }
    }

    /** The checks the run applies are said on stdout and in the log, so nobody takes a non-production run for another. */
    private void announceChecks(Invocation invocation) {
        if (invocation.has(Opt.NON_PRODUCTION)) {
            log.warn("NON-PRODUCTION MODE: the production checks are OFF (self-signed certificate, missing trust anchor, "
                    + "organization id, key policy and AWS account accepted). Never use it in STG or PRO.");
            out.println("checks: NON-PRODUCTION (the production checks are off: never use this mode in STG or PRO)");
        } else {
            log.info("Checks: production");
            out.println("checks: production");
        }
    }

    private static void requireForProduction(Invocation invocation, Opt option) {
        if (!invocation.has(option) || invocation.get(option).isBlank()) {
            throw new OnboardingUsageException("--" + option.flag + " (or " + option.env + ") is required: the "
                    + "production checks apply unless --non-production is given");
        }
    }

    /** The key policy as it is applied, and the SHA-256 of its bytes, which is what is recorded about it. */
    private record KeyPolicy(String json, String sha256) {}

    private KeyPolicy keyPolicy(Invocation invocation) {
        if (invocation.command() != Command.PREPARE || !invocation.has(Opt.KEY_POLICY)) {
            return null;
        }
        byte[] bytes = readBytes(Path.of(invocation.get(Opt.KEY_POLICY)));
        String json = new String(bytes, StandardCharsets.UTF_8);
        try {
            new ObjectMapper().readTree(json);
        } catch (JsonProcessingException _) {
            throw new OnboardingUsageException("--key-policy must be a JSON file");
        }
        return new KeyPolicy(json, sha256Hex(bytes));
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private OnboardingPolicy policy(Invocation invocation) {
        X509Certificate anchor = null;
        if (invocation.has(Opt.TRUST_ANCHOR)) {
            List<X509Certificate> anchors = OwnKeyCertificateValidator.parsePemChain(
                    readString(Path.of(invocation.get(Opt.TRUST_ANCHOR))));
            anchor = anchors.getFirst();
        }
        return new OnboardingPolicy(!invocation.has(Opt.NON_PRODUCTION), anchor, invocation.get(Opt.EXPECTED_ORG_ID));
    }

    private static URI endpoint(String value) {
        try {
            return URI.create(value);
        } catch (IllegalArgumentException _) {
            throw new OnboardingUsageException("--kms-endpoint is not a valid URL");
        }
    }

    private static OnboardingSettings.AuditSinkMode auditSink(Invocation invocation) {
        String value = invocation.has(Opt.AUDIT_SINK) ? invocation.get(Opt.AUDIT_SINK) : "log";
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "log" -> OnboardingSettings.AuditSinkMode.LOG;
            case "outbox" -> OnboardingSettings.AuditSinkMode.OUTBOX;
            default -> throw new OnboardingUsageException("--audit-sink must be log or outbox");
        };
    }

    private OnboardingSettings settings(Invocation invocation, String keyPolicyJson) {
        String password = invocation.env().get(ENV_DB_PASSWORD);
        if (password == null) {
            throw new OnboardingUsageException(ENV_DB_PASSWORD + " is required (the database password is never an argument)");
        }
        String region = invocation.get(Opt.KMS_REGION);
        if (region == null || region.isBlank()) {
            region = invocation.env().get(ENV_AWS_REGION);
        }
        URI endpoint = invocation.has(Opt.KMS_ENDPOINT) ? endpoint(invocation.get(Opt.KMS_ENDPOINT)) : null;
        int days = invocation.has(Opt.DELETION_WINDOW_DAYS)
                ? (int) parseLong(Opt.DELETION_WINDOW_DAYS, invocation.get(Opt.DELETION_WINDOW_DAYS))
                : DEFAULT_DELETION_WINDOW_DAYS;
        String account = invocation.has(Opt.EXPECTED_AWS_ACCOUNT)
                ? ExpectedAwsAccount.parse(invocation.get(Opt.EXPECTED_AWS_ACCOUNT)) : null;
        return new OnboardingSettings(invocation.require(Opt.DB_URL), invocation.require(Opt.DB_USER), password,
                region == null || region.isBlank() ? null : region, endpoint, days, auditSink(invocation),
                keyPolicyJson, !invocation.has(Opt.NON_PRODUCTION), account);
    }

    /** @return the invocation, or {@code null} if help was asked for */
    private static Invocation parse(String[] args, Map<String, String> env) {
        Command command = null;
        for (Command candidate : Command.values()) {
            if (candidate.word.equals(args[0])) {
                command = candidate;
            }
        }
        if (command == null) {
            throw new OnboardingUsageException("unknown command '" + args[0] + "': prepare, import, discard or reconcile");
        }
        Set<Opt> allowed = allowedOptions(command);
        Map<Opt, String> values = new EnumMap<>(Opt.class);
        for (int i = 1; i < args.length; i++) {
            String token = args[i];
            if ("--help".equals(token) || "-h".equals(token)) {
                return null;
            }
            if (!token.startsWith("--")) {
                throw new OnboardingUsageException("unexpected argument '" + token + "'");
            }
            int equals = token.indexOf('=');
            String name = equals < 0 ? token.substring(2) : token.substring(2, equals);
            Opt option = allowed.stream().filter(o -> o.flag.equals(name)).findFirst()
                    .orElseThrow(() -> new OnboardingUsageException("unknown option --" + name + " for " + args[0]));
            if (values.containsKey(option)) {
                throw new OnboardingUsageException("--" + name + " is given twice");
            }
            if (option.isSwitch) {
                if (equals < 0 || isTrue(token.substring(equals + 1))) {
                    values.put(option, "true");
                }
            } else if (equals >= 0) {
                values.put(option, token.substring(equals + 1));
            } else if (i + 1 < args.length) {
                values.put(option, args[++i]);
            } else {
                throw new OnboardingUsageException("--" + name + " needs a value");
            }
        }
        for (Opt option : allowed) {
            if (option.env != null && !values.containsKey(option) && env.get(option.env) != null && !env.get(option.env).isBlank()) {
                if (!option.isSwitch) {
                    values.put(option, env.get(option.env));
                } else if (isTrue(env.get(option.env))) {
                    values.put(option, "true");
                }
            }
        }
        return new Invocation(command, values, env);
    }

    private static Set<Opt> allowedOptions(Command command) {
        Set<Opt> allowed = EnumSet.copyOf(COMMON);
        switch (command) {
            case PREPARE -> allowed.addAll(List.of(Opt.TENANT, Opt.CERT_CHAIN, Opt.OUT_DIR, Opt.ALIAS, Opt.KEY_POLICY,
                    Opt.TRUST_ANCHOR, Opt.EXPECTED_ORG_ID));
            case IMPORT -> allowed.addAll(List.of(Opt.STATE, Opt.KEY_MATERIAL, Opt.IMPORT_TOKEN,
                    Opt.TRUST_ANCHOR, Opt.EXPECTED_ORG_ID));
            case DISCARD -> allowed.add(Opt.STATE);
            case RECONCILE -> allowed.add(Opt.GRACE_SECONDS);
        }
        return allowed;
    }

    private static boolean isTrue(String value) {
        return List.of("true", "1", "yes").contains(value.toLowerCase(Locale.ROOT));
    }

    private static long parseLong(Opt option, String value) {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new OnboardingUsageException("--" + option.flag + " must be a whole number");
        }
    }

    private static String readString(Path file) {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + file, e);
        }
    }

    private static byte[] readBytes(Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + file, e);
        }
    }
}
